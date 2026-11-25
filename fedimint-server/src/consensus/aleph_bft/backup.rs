use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use rand::RngCore as _;
use tracing::{info, warn};

use crate::LOG_CONSENSUS;
use crate::consensus::db::{AlephUnitsKey, AlephUnitsPrefix};

/// File name inside `data_dir` for the recycled, append-only AlephBFT unit
/// backup of the active consensus session.
pub const ALEPH_BACKUP_FILE: &str = "aleph_backup.bin";

const FILE_MAGIC: [u8; 8] = *b"FMALEPH1";
const FILE_HEADER_PREFIX_LEN: usize = 32;
const FILE_HEADER_MAC_LEN: usize = 8;
const FILE_HEADER_LEN: usize = FILE_HEADER_PREFIX_LEN + FILE_HEADER_MAC_LEN;
const NONCE_LEN: usize = 16;

const RECORD_MAGIC: [u8; 4] = *b"UNIT";
const RECORD_CHECKSUM_LEN: usize = 16;
const RECORD_HEADER_LEN: usize = 4 + 4 + RECORD_CHECKSUM_LEN;

/// Identifies a unit in the backup by its encoding.
///
/// AlephBFT passes every unit it adds to its DAG to the [`BackupWriter`],
/// including the units it has just replayed from this backup. Storing those
/// again appends a full copy of the session's units on every restart within a
/// session, and a guardian that keeps restarting in a stalled session then
/// loads every copy at once at its next start. The backup therefore holds each
/// unit once: the writer skips units it already stored, and the reader skips
/// copies written before this rule existed.
fn unit_digest(unit: &[u8]) -> sha256::Hash {
    sha256::Hash::hash(unit)
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn file_header_mac(prefix: &[u8; FILE_HEADER_PREFIX_LEN]) -> [u8; FILE_HEADER_MAC_LEN] {
    let hash = sha256::Hash::hash(prefix);
    let mut mac = [0_u8; FILE_HEADER_MAC_LEN];
    mac.copy_from_slice(&hash.as_byte_array()[..FILE_HEADER_MAC_LEN]);
    mac
}

fn encode_file_header(
    session_index: u64,
    session_nonce: &[u8; NONCE_LEN],
) -> [u8; FILE_HEADER_LEN] {
    let mut prefix = [0_u8; FILE_HEADER_PREFIX_LEN];
    prefix[0..8].copy_from_slice(&FILE_MAGIC);
    prefix[8..16].copy_from_slice(&session_index.to_le_bytes());
    prefix[16..32].copy_from_slice(session_nonce);
    let mac = file_header_mac(&prefix);

    let mut header = [0_u8; FILE_HEADER_LEN];
    header[..FILE_HEADER_PREFIX_LEN].copy_from_slice(&prefix);
    header[FILE_HEADER_PREFIX_LEN..].copy_from_slice(&mac);
    header
}

fn decode_file_header(header: &[u8; FILE_HEADER_LEN]) -> Option<(u64, [u8; NONCE_LEN])> {
    if header[0..8] != FILE_MAGIC {
        return None;
    }

    let mut prefix = [0_u8; FILE_HEADER_PREFIX_LEN];
    prefix.copy_from_slice(&header[..FILE_HEADER_PREFIX_LEN]);
    if header[FILE_HEADER_PREFIX_LEN..] != file_header_mac(&prefix) {
        return None;
    }

    let mut session_bytes = [0_u8; 8];
    session_bytes.copy_from_slice(&header[8..16]);
    let session_index = u64::from_le_bytes(session_bytes);

    let mut session_nonce = [0_u8; NONCE_LEN];
    session_nonce.copy_from_slice(&header[16..32]);

    Some((session_index, session_nonce))
}

fn record_checksum(
    session_index: u64,
    session_nonce: &[u8; NONCE_LEN],
    record_index: u64,
    payload_len: u32,
    payload: &[u8],
) -> [u8; RECORD_CHECKSUM_LEN] {
    let mut engine = sha256::HashEngine::default();
    engine.input(&RECORD_MAGIC);
    engine.input(&session_index.to_le_bytes());
    engine.input(session_nonce);
    engine.input(&record_index.to_le_bytes());
    engine.input(&payload_len.to_le_bytes());
    engine.input(payload);
    let hash = sha256::Hash::from_engine(engine);
    let mut checksum = [0_u8; RECORD_CHECKSUM_LEN];
    checksum.copy_from_slice(&hash.as_byte_array()[..RECORD_CHECKSUM_LEN]);
    checksum
}

fn append_encoded_record(
    buf: &mut Vec<u8>,
    session_index: u64,
    session_nonce: &[u8; NONCE_LEN],
    record_index: u64,
    payload: &[u8],
) -> io::Result<()> {
    let payload_len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "AlephBFT backup unit exceeds u32 length limit",
        )
    })?;
    let checksum = record_checksum(
        session_index,
        session_nonce,
        record_index,
        payload_len,
        payload,
    );

    buf.extend_from_slice(&RECORD_MAGIC);
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(&checksum);
    buf.extend_from_slice(payload);
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

struct FileScan {
    session_nonce: Option<[u8; NONCE_LEN]>,
    units: Vec<Vec<u8>>,
    valid_end_offset: u64,
}

impl FileScan {
    fn empty() -> Self {
        Self {
            session_nonce: None,
            units: Vec::new(),
            valid_end_offset: 0,
        }
    }
}

/// Reads a single record at `offset` from `reader` if it fits within `file_len`
/// and passes magic + checksum validation for `(session_index, session_nonce,
/// record_index)`.
fn read_next_record(
    reader: &mut BufReader<File>,
    file_len: u64,
    offset: u64,
    session_index: u64,
    session_nonce: &[u8; NONCE_LEN],
    record_index: u64,
) -> io::Result<Option<(Vec<u8>, u64)>> {
    let header_len = RECORD_HEADER_LEN as u64;
    if file_len.saturating_sub(offset) < header_len {
        return Ok(None);
    }

    let mut rec_header = [0_u8; RECORD_HEADER_LEN];
    reader.read_exact(&mut rec_header)?;
    if rec_header[0..4] != RECORD_MAGIC {
        return Ok(None);
    }

    let payload_len =
        u32::from_le_bytes([rec_header[4], rec_header[5], rec_header[6], rec_header[7]]);
    let payload_len_u64 = u64::from(payload_len);
    if payload_len_u64 > file_len - offset - header_len {
        return Ok(None);
    }

    let mut payload = vec![0_u8; payload_len as usize];
    reader.read_exact(&mut payload)?;

    let expected = record_checksum(
        session_index,
        session_nonce,
        record_index,
        payload_len,
        &payload,
    );
    if rec_header[8..24] != expected {
        return Ok(None);
    }

    Ok(Some((payload, offset + header_len + payload_len_u64)))
}

fn scan_backup_file(path: &Path, session_index: u64) -> io::Result<FileScan> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(FileScan::empty()),
        Err(err) => return Err(err),
    };

    let file_len = file.metadata()?.len();
    if file_len < FILE_HEADER_LEN as u64 {
        return Ok(FileScan::empty());
    }

    let mut reader = BufReader::new(file);
    let mut header = [0_u8; FILE_HEADER_LEN];
    reader.read_exact(&mut header)?;

    let Some((file_session, session_nonce)) = decode_file_header(&header) else {
        return Ok(FileScan::empty());
    };
    if file_session != session_index {
        return Ok(FileScan::empty());
    }

    let mut offset = FILE_HEADER_LEN as u64;
    let mut record_index = 0_u64;
    let mut units = Vec::new();

    while let Some((payload, next_offset)) = read_next_record(
        &mut reader,
        file_len,
        offset,
        session_index,
        &session_nonce,
        record_index,
    )? {
        units.push(payload);
        offset = next_offset;
        record_index += 1;
    }

    Ok(FileScan {
        session_nonce: Some(session_nonce),
        units,
        valid_end_offset: offset,
    })
}

fn file_has_session_units(path: &Path, session_index: u64) -> io::Result<bool> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };

    let file_len = file.metadata()?.len();
    if file_len < (FILE_HEADER_LEN + RECORD_HEADER_LEN) as u64 {
        return Ok(false);
    }

    let mut reader = BufReader::new(file);
    let mut header = [0_u8; FILE_HEADER_LEN];
    reader.read_exact(&mut header)?;

    let Some((file_session, session_nonce)) = decode_file_header(&header) else {
        return Ok(false);
    };
    if file_session != session_index {
        return Ok(false);
    }

    Ok(read_next_record(
        &mut reader,
        file_len,
        FILE_HEADER_LEN as u64,
        session_index,
        &session_nonce,
        0,
    )?
    .is_some())
}

/// Returns whether any AlephBFT backup units exist for `session_index`,
/// checking both legacy RocksDB `AlephUnitsPrefix` entries (for mid-session
/// upgrades) and the dedicated backup file.
pub async fn has_backup_units(db: &Database, path: &Path, session_index: u64) -> bool {
    let has_legacy = db
        .begin_transaction_nc()
        .await
        .find_by_prefix(&AlephUnitsPrefix)
        .await
        .next()
        .await
        .is_some();
    if has_legacy {
        return true;
    }

    let path = path.to_path_buf();
    match tokio::task::spawn_blocking(move || file_has_session_units(&path, session_index)).await {
        Ok(Ok(has_units)) => has_units,
        Ok(Err(err)) => {
            warn!(
                target: LOG_CONSENSUS,
                session_index,
                %err,
                "Failed to inspect AlephBFT backup file for recovery"
            );
            false
        }
        Err(err) => {
            warn!(
                target: LOG_CONSENSUS,
                session_index,
                %err,
                "AlephBFT backup inspection task failed"
            );
            false
        }
    }
}

/// Resets the dedicated backup file in place for `next_session_index` without
/// shrinking its allocated size, so future sessions overwrite existing blocks
/// without filesystem `i_size` churn.
///
/// If the file does not exist yet (e.g. single-guardian mode or a session that
/// wrote no units), this is a no-op.
pub async fn reset_backup_file(path: &Path, next_session_index: u64) -> io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };

        let header = encode_file_header(next_session_index, &random_nonce());
        let mut reset_bytes = [0_u8; FILE_HEADER_LEN + 4];
        reset_bytes[..FILE_HEADER_LEN].copy_from_slice(&header);
        // Bytes FILE_HEADER_LEN..FILE_HEADER_LEN+4 remain zeroed to invalidate
        // any prior record magic at offset FILE_HEADER_LEN immediately.

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&reset_bytes)?;
        file.sync_data()?;
        Ok(())
    })
    .await
    .map_err(io::Error::other)?
}

pub struct BackupReader {
    db: Database,
    file: Option<(PathBuf, u64)>,
}

impl BackupReader {
    /// Creates a reader backed only by legacy database `AlephUnitsPrefix` rows.
    pub fn new(db: Database) -> Self {
        Self { db, file: None }
    }

    /// Creates a reader that recovers legacy database `AlephUnitsPrefix` rows
    /// (for mid-session upgrades) followed by records for `session_index` from
    /// the dedicated backup file at `path`.
    pub fn with_file(db: Database, path: PathBuf, session_index: u64) -> Self {
        Self {
            db,
            file: Some((path, session_index)),
        }
    }
}

#[async_trait]
impl aleph_bft::BackupReader for BackupReader {
    async fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut stored = 0_usize;
        let mut loaded = BTreeSet::new();
        let mut backup = Vec::new();

        {
            let mut dbtx = self.db.begin_transaction_nc().await;
            let mut units = dbtx.find_by_prefix(&AlephUnitsPrefix).await;
            while let Some((_, unit)) = units.next().await {
                stored += 1;

                // Keep the first copy: it precedes every unit stored after it,
                // so the units still appear after their
                // parents.
                if loaded.insert(unit_digest(&unit)) {
                    backup.extend_from_slice(&unit);
                }
            }
        }

        if let Some((path, session_index)) = &self.file {
            let path = path.clone();
            let session_index = *session_index;
            let scan = tokio::task::spawn_blocking(move || scan_backup_file(&path, session_index))
                .await
                .map_err(io::Error::other)??;

            for unit in scan.units {
                stored += 1;
                if loaded.insert(unit_digest(&unit)) {
                    backup.extend_from_slice(&unit);
                }
            }
        }

        if stored != 0 {
            // Counts of stored and of distinct units only; never unit contents.
            info!(
                target: LOG_CONSENSUS,
                safe_to_share = true,
                units_len = stored,
                unique_units_len = loaded.len(),
                "Recovering from an in-session-shutdown"
            );
        }

        Ok(backup)
    }
}

struct FileWriterState {
    path: PathBuf,
    session_index: u64,
    session_nonce: [u8; NONCE_LEN],
    file: Option<File>,
    write_offset: u64,
    next_record_index: u64,
    header_written: bool,
    needs_dir_sync: bool,
}

impl FileWriterState {
    fn append_units(&mut self, units: &[Vec<u8>]) -> io::Result<()> {
        let mut buf = Vec::new();
        if !self.header_written {
            buf.extend_from_slice(&encode_file_header(self.session_index, &self.session_nonce));
        }

        for (i, unit) in units.iter().enumerate() {
            append_encoded_record(
                &mut buf,
                self.session_index,
                &self.session_nonce,
                self.next_record_index + i as u64,
                unit,
            )?;
        }

        if self.file.is_none() {
            let file = match OpenOptions::new().read(true).write(true).open(&self.path) {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    let created = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(&self.path)?;
                    self.needs_dir_sync = true;
                    created
                }
                Err(err) => return Err(err),
            };
            self.file = Some(file);
        }

        let file = self
            .file
            .as_mut()
            .expect("backup file handle initialized above");
        file.seek(SeekFrom::Start(self.write_offset))?;
        file.write_all(&buf)?;
        file.sync_data()?;

        if self.needs_dir_sync {
            sync_parent_dir(&self.path)?;
            self.needs_dir_sync = false;
        }

        self.write_offset += buf.len() as u64;
        self.next_record_index += units.len() as u64;
        self.header_written = true;
        Ok(())
    }
}

enum WriterBackend {
    LegacyDb { db: Database, units_index: u64 },
    File(Arc<Mutex<FileWriterState>>),
}

pub struct BackupWriter {
    backend: WriterBackend,
    stored: BTreeSet<sha256::Hash>,
}

impl BackupWriter {
    /// Creates a writer backed only by legacy database `AlephUnitsPrefix` rows.
    pub async fn new(db: Database) -> Self {
        let mut units_index = 0;
        let mut stored = BTreeSet::new();

        {
            let mut dbtx = db.begin_transaction_nc().await;
            let mut units = dbtx.find_by_prefix(&AlephUnitsPrefix).await;
            while let Some((key, unit)) = units.next().await {
                units_index = units_index.max(key.0 + 1);
                stored.insert(unit_digest(&unit));
            }
        }

        Self {
            backend: WriterBackend::LegacyDb { db, units_index },
            stored,
        }
    }

    /// Creates a writer that appends new units for `session_index` to the
    /// dedicated recycled backup file at `path`.
    ///
    /// Existing unit digests are loaded from both legacy database
    /// `AlephUnitsPrefix` rows (for mid-session upgrades) and valid records for
    /// `session_index` already present in `path`, so replayed units are never
    /// written again.
    pub async fn with_file(db: Database, path: PathBuf, session_index: u64) -> io::Result<Self> {
        let mut stored = BTreeSet::new();

        {
            let mut dbtx = db.begin_transaction_nc().await;
            let mut units = dbtx.find_by_prefix(&AlephUnitsPrefix).await;
            while let Some((_, unit)) = units.next().await {
                stored.insert(unit_digest(&unit));
            }
        }

        let scan_path = path.clone();
        let scan = tokio::task::spawn_blocking(move || scan_backup_file(&scan_path, session_index))
            .await
            .map_err(io::Error::other)??;

        for unit in &scan.units {
            stored.insert(unit_digest(unit));
        }

        let (session_nonce, write_offset, next_record_index, header_written) =
            if let Some(nonce) = scan.session_nonce {
                (nonce, scan.valid_end_offset, scan.units.len() as u64, true)
            } else {
                (random_nonce(), 0, 0, false)
            };

        let state = FileWriterState {
            path,
            session_index,
            session_nonce,
            file: None,
            write_offset,
            next_record_index,
            header_written,
            needs_dir_sync: false,
        };

        Ok(Self {
            backend: WriterBackend::File(Arc::new(Mutex::new(state))),
            stored,
        })
    }
}

#[async_trait]
impl aleph_bft::BackupWriter for BackupWriter {
    async fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.append_batch(&[data.to_owned()]).await
    }

    /// Stores the new units of the batch in one synced write. AlephBFT passes
    /// every unit it adds to its DAG through here, so syncing each unit alone
    /// costs one disk sync per unit, many per round.
    async fn append_batch(&mut self, items: &[Vec<u8>]) -> io::Result<()> {
        let mut batch_digests = BTreeSet::new();
        let mut new_units: Vec<Vec<u8>> = Vec::new();
        for unit in items {
            let digest = unit_digest(unit);
            if !self.stored.contains(&digest) && batch_digests.insert(digest) {
                new_units.push(unit.clone());
            }
        }
        if new_units.is_empty() {
            return Ok(());
        }

        match &mut self.backend {
            WriterBackend::LegacyDb { db, units_index } => {
                let mut dbtx = db.begin_transaction().await;

                for unit in &new_units {
                    dbtx.insert_new_entry(&AlephUnitsKey(*units_index), unit)
                        .await;
                    *units_index += 1;
                }

                dbtx.commit_tx_result()
                    .await
                    .expect("This is the only place where we write to this key");
            }
            WriterBackend::File(state) => {
                let state = Arc::clone(state);
                tokio::task::spawn_blocking(move || {
                    state
                        .lock()
                        .expect("AlephBFT backup writer mutex poisoned")
                        .append_units(&new_units)
                })
                .await
                .map_err(io::Error::other)??;
            }
        }

        self.stored.extend(batch_digests);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
