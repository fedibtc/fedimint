use std::fs::{self, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};

use aleph_bft::{BackupReader as _, BackupWriter as _};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use tempfile::tempdir;

use super::{ALEPH_BACKUP_FILE, BackupReader, BackupWriter, has_backup_units, reset_backup_file};
use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};

fn unit(byte: u8) -> Vec<u8> {
    vec![byte; 3]
}

async fn stored_rows(db: &Database) -> Vec<(u64, Vec<u8>)> {
    db.begin_transaction_nc()
        .await
        .find_by_prefix(&AlephUnitsPrefix)
        .await
        .map(|(key, unit)| (key.0, unit))
        .collect()
        .await
}

/// AlephBFT hands every unit it replays from the backup to the writer again.
#[tokio::test]
async fn restarts_within_a_session_do_not_store_replayed_units_again() {
    let db: Database = MemDatabase::new().into();

    let mut writer = BackupWriter::new(db.clone()).await;
    for byte in [1, 2, 3] {
        writer.append(&unit(byte)).await.unwrap();
    }

    let mut stored = vec![1, 2, 3];
    for restart in 0..3 {
        assert_eq!(
            BackupReader::new(db.clone()).read().await.unwrap(),
            stored.iter().copied().flat_map(unit).collect::<Vec<_>>()
        );

        // Replay everything loaded, as AlephBFT does after a restart.
        let mut writer = BackupWriter::new(db.clone()).await;
        for &byte in &stored {
            writer.append(&unit(byte)).await.unwrap();
        }
        // The first restart also creates one new unit before the next crash.
        if restart == 0 {
            writer.append(&unit(4)).await.unwrap();
            stored.push(4);
        }
    }

    assert_eq!(
        stored_rows(&db).await,
        vec![(0, unit(1)), (1, unit(2)), (2, unit(3)), (3, unit(4))]
    );
}

/// Databases written before the writer skipped replayed units hold a copy of
/// the session's units per restart.
#[tokio::test]
async fn units_stored_more_than_once_are_loaded_once() {
    let db: Database = MemDatabase::new().into();

    let mut dbtx = db.begin_transaction().await;
    for (index, byte) in [1, 2, 1, 2, 3, 1, 2, 3].into_iter().enumerate() {
        dbtx.insert_new_entry(&AlephUnitsKey(index as u64), &unit(byte))
            .await;
    }
    dbtx.commit_tx().await;

    assert_eq!(
        BackupReader::new(db.clone()).read().await.unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    let mut writer = BackupWriter::new(db.clone()).await;
    for byte in [1, 2, 3, 4] {
        writer.append(&unit(byte)).await.unwrap();
    }

    let rows = stored_rows(&db).await;
    assert_eq!(rows.len(), 9);
    assert_eq!(rows.last(), Some(&(8, unit(4))));
}

/// The saver hands over every unit queued at once, replayed ones included.
#[tokio::test]
async fn a_batch_stores_its_new_units_once_and_in_order() {
    let db: Database = MemDatabase::new().into();

    let mut writer = BackupWriter::new(db.clone()).await;
    writer.append(&unit(1)).await.unwrap();
    writer
        .append_batch(&[unit(3), unit(1), unit(2), unit(3), unit(4)])
        .await
        .unwrap();
    // A batch of units that are all stored already writes nothing.
    writer.append_batch(&[unit(2), unit(4)]).await.unwrap();

    assert_eq!(
        stored_rows(&db).await,
        vec![(0, unit(1)), (1, unit(3)), (2, unit(2)), (3, unit(4))]
    );

    // A writer opened after a restart continues after the last key.
    let mut writer = BackupWriter::new(db.clone()).await;
    writer.append_batch(&[unit(4), unit(5)]).await.unwrap();
    assert_eq!(stored_rows(&db).await.last(), Some(&(4, unit(5))));
}

#[tokio::test]
async fn file_backup_batch_append_dedup_and_restart_recovery() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(ALEPH_BACKUP_FILE);
    let db: Database = MemDatabase::new().into();
    let session = 7;

    assert!(!has_backup_units(&db, &path, session).await);
    assert!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap()
            .is_empty()
    );

    let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
        .await
        .unwrap();
    writer.append(&unit(1)).await.unwrap();
    writer
        .append_batch(&[unit(3), unit(1), unit(2), unit(3), unit(4)])
        .await
        .unwrap();
    let len_after_writes = fs::metadata(&path).unwrap().len();

    // All-duplicate batch performs no write.
    writer.append_batch(&[unit(2), unit(4)]).await.unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), len_after_writes);
    // Dedicated file mode writes nothing into RocksDB.
    assert!(stored_rows(&db).await.is_empty());
    assert!(has_backup_units(&db, &path, session).await);

    let mut expected = vec![unit(1), unit(3), unit(2), unit(4)];
    for restart in 0..3 {
        assert_eq!(
            BackupReader::with_file(db.clone(), path.clone(), session)
                .read()
                .await
                .unwrap(),
            expected.concat()
        );

        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
            .await
            .unwrap();
        // Replay everything already stored; file length must not grow.
        writer.append_batch(&expected).await.unwrap();
        if restart == 0 {
            assert_eq!(fs::metadata(&path).unwrap().len(), len_after_writes);
            writer.append(&unit(5)).await.unwrap();
            expected.push(unit(5));
        }
    }

    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        expected.concat()
    );
    assert!(stored_rows(&db).await.is_empty());
}

#[tokio::test]
async fn file_backup_recovers_prior_units_after_torn_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(ALEPH_BACKUP_FILE);
    let db: Database = MemDatabase::new().into();
    let session = 12;

    let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
        .await
        .unwrap();
    writer
        .append_batch(&[unit(1), unit(2), unit(3)])
        .await
        .unwrap();
    let len_after_three = fs::metadata(&path).unwrap().len();
    writer.append(&unit(4)).await.unwrap();
    let len_after_four = fs::metadata(&path).unwrap().len();
    drop(writer);

    // 1. Corrupt the payload byte of record 3 (simulating a torn sector write).
    {
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(len_after_four - 1)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        file.sync_data().unwrap();
    }
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    // 2. Truncate mid-way into record 3's header/payload.
    {
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(len_after_three + 10).unwrap();
    }
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    // 3. Append a bogus header claiming u32::MAX payload length.
    {
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(len_after_three).unwrap();
        file.seek(SeekFrom::Start(len_after_three)).unwrap();
        file.write_all(b"UNIT").unwrap();
        file.write_all(&u32::MAX.to_le_bytes()).unwrap();
        file.write_all(&[0xAA; 16]).unwrap();
        file.sync_data().unwrap();
    }
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    // A writer opened after the torn tail overwrites from the last valid end
    // and persists record 3 cleanly.
    let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
        .await
        .unwrap();
    writer
        .append_batch(&[unit(1), unit(2), unit(3), unit(4)])
        .await
        .unwrap();
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3), unit(4)].concat()
    );
}

#[tokio::test]
async fn file_backup_recycles_file_across_sessions_and_isolates_crash_before_reset() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(ALEPH_BACKUP_FILE);
    let db: Database = MemDatabase::new().into();

    // Session 5 writes large units so the file grows to > 40 KiB.
    let big_units: Vec<Vec<u8>> = (0_u8..10).map(|i| vec![i; 4096]).collect();
    {
        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), 5)
            .await
            .unwrap();
        writer.append_batch(&big_units).await.unwrap();
    }
    let recycled_size = fs::metadata(&path).unwrap().len();
    assert!(recycled_size > 40_000);

    // Crash right after RocksDB committed SignedSessionOutcome(5) and BEFORE
    // reset_backup_file ran: session 6 must see zero units.
    assert!(!has_backup_units(&db, &path, 6).await);
    assert!(
        BackupReader::with_file(db.clone(), path.clone(), 6)
            .read()
            .await
            .unwrap()
            .is_empty()
    );

    // Normal reset for session 6 preserves file size (no i_size churn).
    reset_backup_file(&path, 6).await.unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), recycled_size);
    assert!(!has_backup_units(&db, &path, 6).await);
    assert!(
        BackupReader::with_file(db.clone(), path.clone(), 6)
            .read()
            .await
            .unwrap()
            .is_empty()
    );

    // Session 6 writes two tiny units: they overwrite in place without
    // changing file size, and stale bytes from session 5 past the tail are
    // never read back.
    {
        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), 6)
            .await
            .unwrap();
        writer.append_batch(&[unit(10), unit(11)]).await.unwrap();
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), recycled_size);
    assert!(has_backup_units(&db, &path, 6).await);
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), 6)
            .read()
            .await
            .unwrap(),
        [unit(10), unit(11)].concat()
    );

    // Session 7 starting even if reset_backup_file never ran after session 6
    // cleanly overwrites from offset 0 while keeping the recycled file size.
    assert!(!has_backup_units(&db, &path, 7).await);
    {
        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), 7)
            .await
            .unwrap();
        writer.append(&unit(99)).await.unwrap();
    }
    assert_eq!(fs::metadata(&path).unwrap().len(), recycled_size);
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), 7)
            .read()
            .await
            .unwrap(),
        unit(99)
    );
}

#[tokio::test]
async fn file_backup_mid_session_upgrade_from_legacy_rocksdb() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(ALEPH_BACKUP_FILE);
    let db: Database = MemDatabase::new().into();
    let session = 42;

    // Pre-upgrade guardian wrote units 1..=3 into RocksDB before restarting on
    // the file-backed binary mid-session.
    {
        let mut dbtx = db.begin_transaction().await;
        for (index, byte) in [1_u8, 2, 3].into_iter().enumerate() {
            dbtx.insert_new_entry(&AlephUnitsKey(index as u64), &unit(byte))
                .await;
        }
        dbtx.commit_tx().await;
    }

    assert!(has_backup_units(&db, &path, session).await);
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3)].concat()
    );

    // On restart, AlephBFT replays legacy units 1..=3 (skipped) and adds 4, 5
    // (written only to the dedicated file, not RocksDB).
    {
        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
            .await
            .unwrap();
        writer
            .append_batch(&[unit(1), unit(2), unit(3)])
            .await
            .unwrap();
        assert!(!path.exists());

        writer.append_batch(&[unit(4), unit(5)]).await.unwrap();
        assert!(path.exists());
    }
    assert_eq!(stored_rows(&db).await.len(), 3);

    // A second crash mid-session recovers legacy units first, then file units,
    // preserving parent-before-child order.
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3), unit(4), unit(5)].concat()
    );

    {
        let mut writer = BackupWriter::with_file(db.clone(), path.clone(), session)
            .await
            .unwrap();
        writer
            .append_batch(&[unit(1), unit(2), unit(3), unit(4), unit(5), unit(6)])
            .await
            .unwrap();
    }
    assert_eq!(stored_rows(&db).await.len(), 3);
    assert_eq!(
        BackupReader::with_file(db.clone(), path.clone(), session)
            .read()
            .await
            .unwrap(),
        [unit(1), unit(2), unit(3), unit(4), unit(5), unit(6)].concat()
    );
}
