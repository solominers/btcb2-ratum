//! Carried work: what an identity left out of a split is owed by the miners who divided the
//! block without it. An identity is left out when its amount would fall under the minimum
//! output or past the output count, and the others then divide the whole value; its window
//! weight in that split is carried and added to its weight in the splits that follow, so it
//! takes a little more of a later block and the others a little less, until it is paid, when
//! the carry is spent. Every sat still reaches miners through a coinbase: the pool holds
//! nothing. The carry changes only when a block is found, by the deltas of the split that
//! block's coinbase used, and those deltas are recorded under the block's hash so a voided
//! block returns the carry it moved.

use super::db::{DbResult as _, write};
use bytes::{Buf as _, BufMut as _};
use log::warn;
use ratum::bitcoin::HASH_SIZE;
use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

/// The carry by identity: the work, and when it last changed.
pub(crate) const CARRY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("carry");
/// The deltas each found block applied, by block hash, for a void to reverse.
pub(crate) const CARRY_DELTAS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("carry_deltas");

/// A carry that has not changed for this long is dropped when the ledger opens: its identity
/// has not mined, been paid or been left out in that time.
pub const PRUNE_AFTER_SECS: u64 = 30 * ratum::SECS_PER_DAY;

/// One identity's change of carry in a split: its window weight, added, when it was left
/// out; its carry, taken, when it was paid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryDelta {
    pub identity: Arc<str>,
    pub work: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    work: u128,
    updated_at: u64,
}

#[derive(Default)]
pub struct Carry {
    by_identity: HashMap<Arc<str>, Entry>,
    db: Option<Arc<Database>>,
}

impl Carry {
    /// The carry in the ledger file, read back, less the entries `PRUNE_AFTER_SECS` old.
    pub fn open(db: Arc<Database>, now: u64) -> io::Result<Self> {
        write(&db, |w| {
            w.open_table(CARRY).db()?;
            w.open_table(CARRY_DELTAS).db()?;
            Ok(())
        })?;
        let mut by_identity = HashMap::new();
        let mut stale = Vec::new();
        {
            let r = db.begin_read().db()?;
            let table = r.open_table(CARRY).db()?;
            for entry in table.iter().db()? {
                let (key, value) = entry.db()?;
                let Some((identity, entry)) = unpack_entry(key.value(), value.value()) else {
                    warn!("skipping a carry row that did not unpack");
                    continue;
                };
                if now.saturating_sub(entry.updated_at) > PRUNE_AFTER_SECS || entry.work == 0 {
                    stale.push(identity);
                } else {
                    by_identity.insert(identity, entry);
                }
            }
        }
        if !stale.is_empty() {
            write(&db, |w| {
                let mut table = w.open_table(CARRY).db()?;
                for identity in &stale {
                    table.remove(identity.as_bytes()).db()?;
                }
                Ok(())
            })?;
        }
        Ok(Self { by_identity, db: Some(db) })
    }

    pub fn get(&self, identity: &str) -> u128 {
        self.by_identity.get(identity).map_or(0, |e| e.work)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Arc<str>, u128)> {
        self.by_identity.iter().map(|(identity, e)| (identity, e.work))
    }

    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    pub fn total(&self) -> u128 {
        self.by_identity.values().map(|e| e.work).sum()
    }

    /// Applies the `deltas` of the split the block at `hash` used, and records them under
    /// the hash; a block already recorded applies nothing again.
    pub fn apply(
        &mut self,
        hash: &[u8; HASH_SIZE],
        deltas: &[CarryDelta],
        now: u64,
    ) -> io::Result<()> {
        if deltas.is_empty() {
            return Ok(());
        }
        if let Some(db) = &self.db {
            let r = db.begin_read().db()?;
            if r.open_table(CARRY_DELTAS).db()?.get(hash.as_slice()).db()?.is_some() {
                return Ok(());
            }
        }
        self.shift(deltas, 1, now);
        self.persist(deltas, Some(hash), None)
    }

    /// Returns the carry the block at `hash` moved, and forgets the block: the deltas it
    /// reversed, or none when the block recorded none.
    pub fn reverse(
        &mut self,
        hash: &[u8; HASH_SIZE],
        now: u64,
    ) -> io::Result<Option<Vec<CarryDelta>>> {
        let Some(db) = &self.db else { return Ok(None) };
        let Some(deltas) = read_deltas(db, hash)? else { return Ok(None) };
        self.shift(&deltas, -1, now);
        self.persist(&deltas, None, Some(hash))?;
        Ok(Some(deltas))
    }

    fn shift(&mut self, deltas: &[CarryDelta], sign: i128, now: u64) {
        for d in deltas {
            let entry = self
                .by_identity
                .entry(Arc::clone(&d.identity))
                .or_insert(Entry { work: 0, updated_at: now });
            let work = entry.work as i128 + d.work * sign;
            entry.work = work.max(0) as u128;
            entry.updated_at = now;
            if entry.work == 0 {
                self.by_identity.remove(&d.identity);
            }
        }
    }

    /// Writes the rows the deltas changed, records `record` and removes `forget`, in one
    /// durable transaction.
    fn persist(
        &self,
        deltas: &[CarryDelta],
        record: Option<&[u8; HASH_SIZE]>,
        forget: Option<&[u8; HASH_SIZE]>,
    ) -> io::Result<()> {
        let Some(db) = &self.db else { return Ok(()) };
        write(db, |w| {
            {
                let mut table = w.open_table(CARRY).db()?;
                for d in deltas {
                    match self.by_identity.get(&d.identity) {
                        Some(entry) => {
                            table
                                .insert(d.identity.as_bytes(), pack_entry(entry).as_slice())
                                .db()?;
                        }
                        None => {
                            table.remove(d.identity.as_bytes()).db()?;
                        }
                    }
                }
            }
            let mut recorded = w.open_table(CARRY_DELTAS).db()?;
            if let Some(hash) = record {
                recorded.insert(hash.as_slice(), pack_deltas(deltas).as_slice()).db()?;
            }
            if let Some(hash) = forget {
                recorded.remove(hash.as_slice()).db()?;
            }
            Ok(())
        })
    }
}

/// `Carry::reverse` on a ledger file no pool has open: what a void run on the file does.
pub fn reverse_in_file(
    db: &Database,
    hash: &[u8; HASH_SIZE],
    now: u64,
) -> io::Result<Option<Vec<CarryDelta>>> {
    let Some(deltas) = read_deltas(db, hash)? else { return Ok(None) };
    write(db, |w| {
        {
            let mut table = w.open_table(CARRY).db()?;
            for d in &deltas {
                let current = table
                    .get(d.identity.as_bytes())
                    .db()?
                    .and_then(|v| unpack_entry(d.identity.as_bytes(), v.value()))
                    .map_or(0, |(_, e)| e.work);
                let work = (current as i128 - d.work).max(0) as u128;
                if work == 0 {
                    table.remove(d.identity.as_bytes()).db()?;
                } else {
                    let entry = Entry { work, updated_at: now };
                    table.insert(d.identity.as_bytes(), pack_entry(&entry).as_slice()).db()?;
                }
            }
        }
        w.open_table(CARRY_DELTAS).db()?.remove(hash.as_slice()).db()?;
        Ok(())
    })?;
    Ok(Some(deltas))
}

fn read_deltas(db: &Database, hash: &[u8; HASH_SIZE]) -> io::Result<Option<Vec<CarryDelta>>> {
    let r = db.begin_read().db()?;
    let table = match r.open_table(CARRY_DELTAS) {
        Ok(table) => table,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(io::Error::other(e.to_string())),
    };
    let Some(row) = table.get(hash.as_slice()).db()? else { return Ok(None) };
    Ok(Some(unpack_deltas(row.value())))
}

fn pack_entry(e: &Entry) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.put_u128_le(e.work);
    v.put_u64_le(e.updated_at);
    v
}

fn unpack_entry(key: &[u8], mut value: &[u8]) -> Option<(Arc<str>, Entry)> {
    if value.len() < 24 {
        return None;
    }
    let work = value.get_u128_le();
    let updated_at = value.get_u64_le();
    Some((Arc::from(std::str::from_utf8(key).ok()?), Entry { work, updated_at }))
}

/// Each delta as its identity's length, the identity and the work.
fn pack_deltas(deltas: &[CarryDelta]) -> Vec<u8> {
    let mut v = Vec::new();
    for d in deltas {
        v.put_u16_le(d.identity.len() as u16);
        v.put_slice(d.identity.as_bytes());
        v.put_i128_le(d.work);
    }
    v
}

fn unpack_deltas(mut bytes: &[u8]) -> Vec<CarryDelta> {
    let mut out = Vec::new();
    while bytes.len() >= 2 {
        let len = bytes.get_u16_le() as usize;
        if bytes.len() < len + 16 {
            break;
        }
        let identity = String::from_utf8_lossy(&bytes[..len]).into_owned();
        bytes.advance(len);
        let work = bytes.get_i128_le();
        out.push(CarryDelta { identity: Arc::from(identity), work });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delta(identity: &str, work: i128) -> CarryDelta {
        CarryDelta { identity: Arc::from(identity), work }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ratum-carry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn a_memory_carry_applies_and_never_goes_under_zero() {
        let mut c = Carry::default();
        c.apply(&[1; 32], &[delta("a", 10), delta("b", 5)], 100).unwrap();
        assert_eq!((c.get("a"), c.get("b"), c.get("c")), (10, 5, 0));
        c.apply(&[2; 32], &[delta("a", -30), delta("b", 1)], 101).unwrap();
        assert_eq!((c.get("a"), c.get("b"), c.len(), c.total()), (0, 6, 1, 6));
        assert_eq!(c.reverse(&[1; 32], 102).unwrap(), None, "no file, no record");
        assert!(c.apply(&[3; 32], &[], 103).is_ok());
    }

    #[test]
    fn a_file_carry_records_each_block_once_and_a_void_returns_what_it_moved() {
        let path = scratch("carry.redb");
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let mut c = Carry::open(Arc::clone(&db), 1_000).unwrap();
        c.apply(&[1; 32], &[delta("a", 10), delta("b", 5)], 1_000).unwrap();
        c.apply(&[1; 32], &[delta("a", 10)], 1_000).unwrap();
        assert_eq!(c.get("a"), 10, "the same block applies nothing twice");
        c.apply(&[2; 32], &[delta("a", -10), delta("c", 7)], 1_001).unwrap();
        assert_eq!((c.get("a"), c.get("b"), c.get("c")), (0, 5, 7));

        let reopened = Carry::open(Arc::clone(&db), 1_002).unwrap();
        assert_eq!((reopened.get("a"), reopened.get("b"), reopened.get("c")), (0, 5, 7));
        assert_eq!(reopened.len(), 2, "a zero entry is not stored");

        let mut c = reopened;
        let reversed = c.reverse(&[2; 32], 1_003).unwrap().unwrap();
        assert_eq!(reversed, [delta("a", -10), delta("c", 7)]);
        assert_eq!((c.get("a"), c.get("b"), c.get("c")), (10, 5, 0));
        assert_eq!(c.reverse(&[2; 32], 1_004).unwrap(), None, "forgotten once reversed");

        drop(c);
        let on_file = reverse_in_file(&db, &[1; 32], 1_005).unwrap().unwrap();
        assert_eq!(on_file, [delta("a", 10), delta("b", 5)]);
        let after = Carry::open(Arc::clone(&db), 1_006).unwrap();
        assert_eq!(after.len(), 0, "everything the two blocks moved is returned");
        assert_eq!(reverse_in_file(&db, &[1; 32], 1_007).unwrap(), None);
        drop(after);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_stale_carry_is_pruned_when_the_file_opens() {
        let path = scratch("prune.redb");
        let db = Arc::new(redb::Database::create(&path).unwrap());
        let mut c = Carry::open(Arc::clone(&db), 1_000).unwrap();
        c.apply(&[1; 32], &[delta("old", 3)], 1_000).unwrap();
        c.apply(&[2; 32], &[delta("new", 4)], 1_000 + PRUNE_AFTER_SECS).unwrap();
        drop(c);
        let later = Carry::open(Arc::clone(&db), 2_001 + PRUNE_AFTER_SECS).unwrap();
        assert_eq!((later.get("old"), later.get("new")), (0, 4));
        drop(later);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn deltas_pack_and_unpack() {
        let deltas = vec![delta("bcrt1qa", 1 << 70), delta("", -3), delta("x", 0)];
        assert_eq!(unpack_deltas(&pack_deltas(&deltas)), deltas);
        assert!(unpack_deltas(&[1, 0, b'a']).is_empty(), "a short row stops");
    }
}
