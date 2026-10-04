//! RocksDB-backed persistent [`Database`](crate::Database) implementation.

use alloc::vec::Vec;
use core::fmt;
use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch};

use crate::{ALL_COLUMNS, Batch, BatchOp, Column, ColumnSnapshot, Database};

/// Error returned by [`RocksDbDatabase`].
#[derive(Debug)]
pub enum RocksDbError {
    /// RocksDB returned an error.
    RocksDb(rocksdb::Error),
    /// The database was opened without the expected column family.
    MissingColumn(Column),
}

impl fmt::Display for RocksDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RocksDb(err) => write!(f, "rocksdb error: {err}"),
            Self::MissingColumn(column) => {
                write!(f, "rocksdb column family {} is missing", column.name())
            }
        }
    }
}

impl std::error::Error for RocksDbError {}

impl From<rocksdb::Error> for RocksDbError {
    fn from(value: rocksdb::Error) -> Self {
        Self::RocksDb(value)
    }
}

/// Persistent RocksDB storage backend.
pub struct RocksDbDatabase {
    db: DB,
}

impl fmt::Debug for RocksDbDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rocksdb::DB` does not implement `Debug` and exposing its
        // internals would not be useful anyway; a stable opaque label
        // keeps consumers like the node `Debug` derives happy.
        f.debug_struct("RocksDbDatabase").finish_non_exhaustive()
    }
}

impl RocksDbDatabase {
    /// Opens or creates a database at `path`, creating every Neutrino
    /// column family if it is missing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RocksDbError> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);

        let descriptors = ALL_COLUMNS
            .iter()
            .map(|column| ColumnFamilyDescriptor::new(column.name(), Options::default()));
        let db = DB::open_cf_descriptors(&options, path, descriptors)?;
        Ok(Self { db })
    }

    fn cf(&self, column: Column) -> Result<impl rocksdb::AsColumnFamilyRef + '_, RocksDbError> {
        self.db
            .cf_handle(column.name())
            .ok_or(RocksDbError::MissingColumn(column))
    }
}

impl Database for RocksDbDatabase {
    type Error = RocksDbError;

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let cf = self.cf(column)?;
        self.db.get_cf(&cf, key).map_err(Into::into)
    }

    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let cf = self.cf(column)?;
        self.db.put_cf(&cf, key, value).map_err(Into::into)
    }

    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        let cf = self.cf(column)?;
        self.db.delete_cf(&cf, key).map_err(Into::into)
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        let mut write_batch = WriteBatch::default();
        for op in batch.into_operations() {
            match op {
                BatchOp::Put { column, key, value } => {
                    let cf = self.cf(column)?;
                    write_batch.put_cf(&cf, key, value);
                }
                BatchOp::Delete { column, key } => {
                    let cf = self.cf(column)?;
                    write_batch.delete_cf(&cf, key);
                }
            }
        }
        self.db.write(write_batch).map_err(Into::into)
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        let mut write_batch = WriteBatch::default();
        for op in batch.into_operations() {
            match op {
                BatchOp::Put { column, key, value } => {
                    write_batch.put_cf(&self.cf(column)?, key, value);
                }
                BatchOp::Delete { column, key } => {
                    write_batch.delete_cf(&self.cf(column)?, key);
                }
            }
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        options.disable_wal(false);
        self.db.write_opt(write_batch, &options).map_err(Into::into)
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        let cf = self.cf(column)?;
        let mut out = Vec::new();
        for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
            let (key, value) = entry?;
            out.push((key.into_vec(), value.into_vec()));
        }
        Ok(out)
    }

    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        let cf = self.cf(column)?;
        let mut out = Vec::new();
        for entry in self
            .db
            .iterator_cf(&cf, IteratorMode::From(prefix, rocksdb::Direction::Forward))
        {
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key.into_vec(), value.into_vec()));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn get(db: &RocksDbDatabase, column: Column, key: &[u8]) -> Option<Vec<u8>> {
        db.get(column, key).expect("rocksdb get succeeds")
    }

    fn temp_db_path(test_name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "neutrino-storage-{test_name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn rocksdb_put_get_delete_roundtrip() {
        let path = temp_db_path("roundtrip");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::Meta, b"chain", b"a").expect("put");
            assert_eq!(get(&db, Column::Meta, b"chain"), Some(b"a".to_vec()));
            db.delete(Column::Meta, b"chain").expect("delete");
            assert_eq!(get(&db, Column::Meta, b"chain"), None);
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_empty_key_and_empty_value_roundtrip() {
        let path = temp_db_path("empty-key-value");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::StateValues, b"", b"").expect("put empty");
            assert_eq!(get(&db, Column::StateValues, b""), Some(Vec::new()));
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_binary_keys_and_values_are_preserved() {
        let path = temp_db_path("binary");
        let key = [0, 255, 1, 254, 2, 253];
        let value = [255, 0, 128, 64, 32, 16, 8, 4, 2, 1];
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::TrieNodes, &key, &value).expect("put binary");
            assert_eq!(get(&db, Column::TrieNodes, &key), Some(value.to_vec()));
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_all_columns_are_created_and_isolated() {
        let path = temp_db_path("all-columns");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            for (index, column) in ALL_COLUMNS.iter().copied().enumerate() {
                db.put(
                    column,
                    b"shared-key",
                    &[u8::try_from(index).expect("index fits u8")],
                )
                .expect("put column value");
            }

            for (index, column) in ALL_COLUMNS.iter().copied().enumerate() {
                assert_eq!(
                    get(&db, column, b"shared-key"),
                    Some(vec![u8::try_from(index).expect("index fits u8")])
                );
            }
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_persists_values_after_reopen() {
        let path = temp_db_path("persist");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::Headers, b"h", b"header").expect("put");
        }
        {
            let db = RocksDbDatabase::open(&path).expect("reopen rocksdb");
            assert_eq!(get(&db, Column::Headers, b"h"), Some(b"header".to_vec()));
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn durable_signing_batch_preserves_prior_finality_after_abrupt_exit() {
        use std::io::{BufRead, Read, Write};
        use std::process::Stdio;

        const CHILD_PATH: &str = "NEUTRINO_DURABILITY_CHILD_DB";
        const SYNCED: &str = "NEUTRINO_DURABILITY_SYNCED\n";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let mut db = RocksDbDatabase::open(path).expect("open child database");
            let mut finality = Batch::new();
            finality.put(Column::Finalized, b"latest_chunk_id", 9_u64.to_be_bytes());
            db.write_batch(finality).expect("ordinary finality write");
            let mut signing = Batch::new();
            signing.put(Column::SigningJournal, b"identity", b"reserved-message");
            signing.put(Column::BftSessions, b"chunk", b"saved-session");
            db.write_batch_durable(signing)
                .expect("synchronize signing and prior WAL");
            // The parent kills this process only after the synchronized write.
            // Waiting avoids libc/C++ exit handlers and normal database flushes.
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(SYNCED.as_bytes())
                .expect("signal synchronized write");
            stdout.flush().expect("flush synchronization signal");
            std::io::stdin()
                .read_exact(&mut [0])
                .expect("parent keeps input open until terminating child");
            panic!("parent must terminate the synchronized child without shutdown");
        }
        let path = temp_db_path("durable-abrupt-exit");
        let mut child = std::process::Command::new(
            std::env::current_exe().expect("test executable"),
        )
        .arg("--exact")
        .arg("rocks::tests::durable_signing_batch_preserves_prior_finality_after_abrupt_exit")
        .arg("--nocapture")
        .env(CHILD_PATH, &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run crash child");
        let mut output = std::io::BufReader::new(child.stdout.take().expect("child output pipe"));
        let mut transcript = String::new();
        while !transcript.ends_with(SYNCED) {
            assert_ne!(
                output
                    .read_line(&mut transcript)
                    .expect("read synchronization signal"),
                0,
                "child exited before synchronizing its write: {transcript}"
            );
        }
        child.kill().expect("terminate without database shutdown");
        let status = child.wait().expect("reap terminated child");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(9),
                "child must be killed with SIGKILL"
            );
        }
        #[cfg(not(unix))]
        assert!(!status.success(), "child must be forcibly terminated");
        let db = RocksDbDatabase::open(&path).expect("recover child WAL");
        assert_eq!(
            get(&db, Column::Finalized, b"latest_chunk_id"),
            Some(9_u64.to_be_bytes().to_vec())
        );
        assert_eq!(
            get(&db, Column::SigningJournal, b"identity"),
            Some(b"reserved-message".to_vec())
        );
        assert_eq!(
            get(&db, Column::BftSessions, b"chunk"),
            Some(b"saved-session".to_vec())
        );
        drop(db);
        fs::remove_dir_all(&path).expect("remove crash child database");
    }

    #[test]
    fn rocksdb_delete_persists_after_reopen() {
        let path = temp_db_path("delete-persists");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::Headers, b"h", b"header").expect("put");
            db.delete(Column::Headers, b"h").expect("delete");
        }
        {
            let db = RocksDbDatabase::open(&path).expect("reopen rocksdb");
            assert_eq!(get(&db, Column::Headers, b"h"), None);
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_batch_is_atomic_and_ordered() {
        let path = temp_db_path("batch");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            let mut batch = Batch::new();
            batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
            batch.put(Column::Meta, b"a".to_vec(), b"2".to_vec());
            batch.put(Column::Blocks, b"a".to_vec(), b"block".to_vec());
            db.write_batch(batch).expect("write batch");
            assert_eq!(get(&db, Column::Meta, b"a"), Some(b"2".to_vec()));
            assert_eq!(get(&db, Column::Blocks, b"a"), Some(b"block".to_vec()));
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_batch_final_delete_wins() {
        let path = temp_db_path("batch-final-delete");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            let mut batch = Batch::new();
            batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
            batch.delete(Column::Meta, b"a".to_vec());
            db.write_batch(batch).expect("write batch");
            assert_eq!(get(&db, Column::Meta, b"a"), None);
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_batch_delete_then_put_wins() {
        let path = temp_db_path("batch-delete-put");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.put(Column::Meta, b"a", b"old").expect("put old");
            let mut batch = Batch::new();
            batch.delete(Column::Meta, b"a".to_vec());
            batch.put(Column::Meta, b"a".to_vec(), b"new".to_vec());
            db.write_batch(batch).expect("write batch");
            assert_eq!(get(&db, Column::Meta, b"a"), Some(b"new".to_vec()));
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }

    #[test]
    fn rocksdb_deleting_missing_key_is_noop() {
        let path = temp_db_path("missing-delete");
        {
            let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
            db.delete(Column::Meta, b"missing").expect("delete missing");
            assert_eq!(get(&db, Column::Meta, b"missing"), None);
        }
        fs::remove_dir_all(&path).expect("remove temp rocksdb");
    }
}
