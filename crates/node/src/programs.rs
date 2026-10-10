//! On-chain program distribution (design 24, phase 3).
//!
//! Upgrade artifacts, the runtime WASM and the five Guest ELFs, travel in the
//! block body's program lane as bounded pieces committed by content hash.
//! This store reassembles pieces from imported blocks, accepts an artifact
//! only when the BLAKE3 hash of its complete bytes equals the announced
//! content hash, persists accepted artifacts beside the database, and feeds
//! locally published files into produced blocks piece by piece.
//!
//! Nothing here decides what to trust: governance names content hashes and
//! Guest digests, the node installs an artifact only when governance named
//! it, and SP1 setup of an installed ELF is compared against the approved
//! digest before any proof is attempted under it.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use neutrino_consensus_types::{
    MAX_PROGRAM_BYTES, MAX_PROGRAM_PIECE_BYTES, ProgramPiece, evidence::MerkleOpening,
    program_content_hash,
};
use neutrino_primitives::{Hash, blake3_256, merkle_root_of_hashes};

/// Lowercase hex of a content hash.
#[must_use]
pub fn hex_hash(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Split an artifact into authenticated pieces. `None` when the artifact is
/// empty or over the protocol bound.
#[must_use]
pub fn split_into_pieces(bytes: &[u8]) -> Option<Vec<ProgramPiece>> {
    if bytes.is_empty() || bytes.len() > MAX_PROGRAM_BYTES as usize {
        return None;
    }
    let total_len = u32::try_from(bytes.len()).ok()?;
    let leaves: Vec<Hash> = bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    let root = merkle_root_of_hashes(&leaves);
    bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            Some(ProgramPiece {
                root,
                total_len,
                offset: u32::try_from(index * MAX_PROGRAM_PIECE_BYTES).ok()?,
                bytes: chunk.to_vec(),
                opening: MerkleOpening::build(&leaves, index)?,
            })
        })
        .collect()
}

/// Parse the lowercase hex produced by [`hex_hash`].
#[must_use]
pub fn parse_hex_hash(text: &str) -> Option<Hash> {
    hex::FromHex::from_hex(text).ok()
}

/// Content hash governance names for an artifact. `None` for an empty or
/// oversized artifact.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> Option<Hash> {
    let total_len = u32::try_from(bytes.len()).ok()?;
    if bytes.is_empty() || total_len > MAX_PROGRAM_BYTES {
        return None;
    }
    let leaves: Vec<Hash> = bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    Some(program_content_hash(
        total_len,
        merkle_root_of_hashes(&leaves),
    ))
}

/// Memory reserved for artifacts still being assembled, counted by their
/// declared lengths so a half-received artifact cannot exceed its share.
const MAX_PARTIAL_BYTES: u64 = 128 * 1024 * 1024;
/// Complete, verified artifacts kept in memory until installed.
const MAX_COMPLETE_ARTIFACTS: usize = 8;
/// Bytes of complete artifacts kept in memory until installed.
const MAX_COMPLETE_BYTES: usize = 64 * 1024 * 1024;

/// What an artifact's leading bytes say it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// A `\0asm` WebAssembly module: a runtime.
    Wasm,
    /// A `\x7fELF` executable: an SP1 Guest.
    Elf,
    /// Neither; never installed.
    Unknown,
}

impl ArtifactKind {
    /// Classify by magic bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"\0asm") {
            Self::Wasm
        } else if bytes.starts_with(b"\x7fELF") {
            Self::Elf
        } else {
            Self::Unknown
        }
    }
}

struct Partial {
    total_len: u32,
    received: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
}

/// A locally published file being streamed into produced blocks.
struct Publishing {
    path: PathBuf,
    content_hash: Hash,
    pieces: Vec<ProgramPiece>,
    next: usize,
}

/// Observable store state for operators.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramStoreStatus {
    /// `(content hash, bytes received, total bytes)` of artifacts in flight.
    pub assembling: Vec<(Hash, u32, u32)>,
    /// Complete, verified artifacts not yet installed.
    pub complete: Vec<Hash>,
    /// Artifacts persisted on disk, by content hash and kind.
    pub persisted: Vec<(Hash, ArtifactKind)>,
    /// `(content hash, pieces sent, total pieces)` of the file being published.
    pub publishing: Option<(Hash, u32, u32)>,
    /// Files queued for publication after the current one.
    pub publish_queue: Vec<String>,
}

/// Reassembly, persistence and publication of program artifacts.
pub struct ProgramStore {
    dir: Option<PathBuf>,
    partial: Mutex<BTreeMap<Hash, Partial>>,
    complete: Mutex<BTreeMap<Hash, Arc<Vec<u8>>>>,
    publishing: Mutex<Option<Publishing>>,
}

impl ProgramStore {
    /// Memory-only store: nothing persists and nothing is published.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self {
            dir: None,
            partial: Mutex::new(BTreeMap::new()),
            complete: Mutex::new(BTreeMap::new()),
            publishing: Mutex::new(None),
        }
    }

    /// Store rooted at `dir`: installed artifacts live in `dir`, files dropped
    /// into `dir/publish` are streamed into produced blocks and moved to
    /// `dir/published` once their last piece has been produced.
    ///
    /// # Errors
    /// Returns the I/O error of creating the directories.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir.join("publish"))?;
        fs::create_dir_all(dir.join("published"))?;
        Ok(Self {
            dir: Some(dir.to_path_buf()),
            partial: Mutex::new(BTreeMap::new()),
            complete: Mutex::new(BTreeMap::new()),
            publishing: Mutex::new(None),
        })
    }

    fn artifact_path(dir: &Path, hash: &Hash) -> PathBuf {
        dir.join(format!("{}.bin", hex_hash(hash)))
    }

    /// Persisted artifacts whose bytes still hash to their file name.
    #[must_use]
    pub fn persisted(&self) -> Vec<(Hash, Vec<u8>)> {
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "bin") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            match content_hash(&bytes) {
                Some(hash) if Self::artifact_path(dir, &hash) == path => found.push((hash, bytes)),
                _ => {
                    let _ = fs::remove_file(path);
                }
            }
        }
        found.sort_by_key(|(hash, _)| *hash);
        found
    }

    /// Persisted artifacts by file name and leading bytes, without reading or
    /// hashing their contents; cheap enough for an unauthenticated status call.
    fn persisted_summary(&self) -> Vec<(Hash, ArtifactKind)> {
        use std::io::Read as _;
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(stem) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".bin"))
            else {
                continue;
            };
            let Some(hash) = parse_hex_hash(stem) else {
                continue;
            };
            let mut magic = [0_u8; 4];
            let kind = fs::File::open(&path)
                .and_then(|mut file| file.read_exact(&mut magic))
                .map_or(ArtifactKind::Unknown, |()| ArtifactKind::of(&magic));
            found.push((hash, kind));
        }
        found.sort_by_key(|(hash, _)| *hash);
        found
    }

    /// Absorb the program lane of an imported block, keeping only pieces of
    /// artifacts in `wanted` that authenticate against their content hash.
    /// Returns the content hashes of artifacts completed by these pieces.
    pub fn absorb(&self, pieces: &[ProgramPiece], wanted: &BTreeSet<Hash>) -> Vec<Hash> {
        let mut completed = Vec::new();
        let mut partial = self
            .partial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Reservations follow governance: an artifact no longer named frees
        // its share immediately, so a stale proposal cannot starve a live one.
        partial.retain(|hash, _| wanted.contains(hash));
        for piece in pieces {
            let hash = piece.content_hash();
            if !wanted.contains(&hash) || !piece.authenticates() {
                continue;
            }
            if self
                .complete
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(&hash)
                || self.is_persisted(&hash)
            {
                continue;
            }
            if !partial.contains_key(&hash) {
                let reserved: u64 = partial
                    .values()
                    .map(|entry| u64::from(entry.total_len))
                    .sum();
                if reserved + u64::from(piece.total_len) > MAX_PARTIAL_BYTES {
                    continue;
                }
                partial.insert(
                    hash,
                    Partial {
                        total_len: piece.total_len,
                        received: BTreeMap::new(),
                        bytes: 0,
                    },
                );
            }
            let entry = partial.get_mut(&hash).expect("inserted above");
            if entry.received.contains_key(&piece.offset) {
                continue;
            }
            entry.bytes += piece.bytes.len();
            entry.received.insert(piece.offset, piece.bytes.clone());
            if let Some(bytes) = Self::assembled(entry) {
                partial.remove(&hash);
                // Every piece authenticated against the root, so the whole
                // artifact does too; recomputing is a cheap final check.
                if content_hash(&bytes) == Some(hash) {
                    self.accept(hash, bytes);
                    completed.push(hash);
                }
            }
        }
        drop(partial);
        completed
    }

    /// Concatenate contiguous pieces once they cover the whole artifact.
    fn assembled(entry: &Partial) -> Option<Vec<u8>> {
        if entry.bytes != entry.total_len as usize {
            return None;
        }
        let mut bytes = Vec::with_capacity(entry.total_len as usize);
        for (offset, chunk) in &entry.received {
            if *offset as usize != bytes.len() {
                return None;
            }
            bytes.extend_from_slice(chunk);
        }
        (bytes.len() == entry.total_len as usize).then_some(bytes)
    }

    /// Keep a verified artifact in memory until the installer decides.
    fn accept(&self, hash: Hash, bytes: Vec<u8>) {
        let mut complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        complete.insert(hash, Arc::new(bytes));
        while complete.len() > MAX_COMPLETE_ARTIFACTS
            || complete.values().map(|bytes| bytes.len()).sum::<usize>() > MAX_COMPLETE_BYTES
        {
            let oldest = *complete.keys().next().expect("nonempty");
            complete.remove(&oldest);
        }
        drop(complete);
    }

    fn is_persisted(&self, hash: &Hash) -> bool {
        self.dir
            .as_ref()
            .is_some_and(|dir| Self::artifact_path(dir, hash).exists())
    }

    /// Complete artifacts awaiting installation.
    #[must_use]
    pub fn complete(&self) -> Vec<(Hash, Arc<Vec<u8>>)> {
        self.complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(hash, bytes)| (*hash, Arc::clone(bytes)))
            .collect()
    }

    /// Persist an artifact that governance named and the node installed, so
    /// a restart reinstalls exactly the approved set and nothing else.
    pub fn persist(&self, hash: &Hash, bytes: &[u8]) {
        let Some(dir) = &self.dir else {
            return;
        };
        let path = Self::artifact_path(dir, hash);
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
        let _ = fs::remove_file(tmp);
    }

    /// Forget an artifact once installed or rejected.
    pub fn mark_installed(&self, hash: &Hash) {
        self.complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(hash);
    }

    /// Delete a persisted artifact the chain no longer names.
    pub fn forget_persisted(&self, hash: &Hash) {
        if let Some(dir) = &self.dir {
            let _ = fs::remove_file(Self::artifact_path(dir, hash));
        }
    }

    /// Bytes of a complete or persisted artifact.
    #[must_use]
    pub fn artifact(&self, hash: &Hash) -> Option<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(hash)
        {
            return Some(Arc::clone(bytes));
        }
        let dir = self.dir.as_ref()?;
        let bytes = fs::read(Self::artifact_path(dir, hash)).ok()?;
        (content_hash(&bytes) == Some(*hash)).then(|| Arc::new(bytes))
    }

    /// Next pieces for a produced block, at most `max_pieces`, drawn from the
    /// publish directory.
    #[must_use]
    pub fn next_pieces(&self, max_pieces: usize) -> Vec<ProgramPiece> {
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let mut publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut pieces = Vec::new();
        while pieces.len() < max_pieces {
            if publishing.is_none() {
                *publishing = Self::next_publish_file(dir);
            }
            let Some(current) = publishing.as_mut() else {
                break;
            };
            pieces.push(current.pieces[current.next].clone());
            current.next += 1;
            if current.next >= current.pieces.len() {
                let done = publishing.take().expect("current publication");
                let target = dir.join("published").join(
                    done.path
                        .file_name()
                        .map_or_else(|| "artifact".into(), std::ffi::OsStr::to_os_string),
                );
                let _ = fs::rename(&done.path, target);
            }
        }
        drop(publishing);
        pieces
    }

    fn next_publish_file(dir: &Path) -> Option<Publishing> {
        let mut files: Vec<PathBuf> = fs::read_dir(dir.join("publish"))
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        for path in files {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Some(pieces) = split_into_pieces(&bytes) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            return Some(Publishing {
                content_hash: pieces[0].content_hash(),
                path,
                pieces,
                next: 0,
            });
        }
        None
    }

    /// Operator-facing snapshot.
    #[must_use]
    pub fn status(&self) -> ProgramStoreStatus {
        let assembling = self
            .partial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(hash, entry)| {
                (
                    *hash,
                    u32::try_from(entry.bytes).unwrap_or(u32::MAX),
                    entry.total_len,
                )
            })
            .collect();
        let complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        let persisted = self.persisted_summary();
        let publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|current| {
                (
                    current.content_hash,
                    u32::try_from(current.next).unwrap_or(u32::MAX),
                    u32::try_from(current.pieces.len()).unwrap_or(u32::MAX),
                )
            });
        let publish_queue = self
            .dir
            .as_ref()
            .and_then(|dir| fs::read_dir(dir.join("publish")).ok())
            .map(|entries| {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect();
                names.sort();
                names
            })
            .unwrap_or_default();
        ProgramStoreStatus {
            assembling,
            complete,
            persisted,
            publishing,
            publish_queue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wanted(bytes: &[u8]) -> BTreeSet<Hash> {
        BTreeSet::from([content_hash(bytes).unwrap()])
    }

    #[test]
    fn pieces_assemble_in_any_order_and_forged_or_unwanted_pieces_are_dropped() {
        let store = ProgramStore::in_memory();
        let artifact: Vec<u8> = (0..(MAX_PROGRAM_PIECE_BYTES * 2 + 3000))
            .map(|i| u8::try_from(i % 251).expect("below 256"))
            .collect();
        let hash = content_hash(&artifact).unwrap();
        let mut pieces = split_into_pieces(&artifact).unwrap();
        assert_eq!(pieces.len(), 3);
        assert!(pieces.iter().all(ProgramPiece::authenticates));
        pieces.reverse();
        let wanted = wanted(&artifact);
        assert_eq!(store.absorb(&pieces[..2], &wanted), Vec::<Hash>::new());
        // A forged piece for this artifact never enters the assembly.
        let mut forged = pieces[2].clone();
        forged.bytes[0] ^= 1;
        assert!(!forged.authenticates());
        assert_eq!(store.absorb(&[forged], &wanted), Vec::<Hash>::new());
        assert_eq!(store.absorb(&pieces[2..], &wanted), vec![hash]);
        assert_eq!(store.artifact(&hash).as_deref(), Some(&artifact));
        // Artifacts governance never named are not assembled at all.
        let other = vec![7_u8; 2000];
        let other_pieces = split_into_pieces(&other).unwrap();
        assert_eq!(store.absorb(&other_pieces, &wanted), Vec::<Hash>::new());
        assert_eq!(store.status().assembling.len(), 0);
    }

    #[test]
    fn reserved_lengths_bound_assembly_memory() {
        let store = ProgramStore::in_memory();
        // Nine 16 MiB declarations exceed the 128 MiB budget: the ninth is
        // refused even though only one piece of each has arrived.
        let mut wanted = BTreeSet::new();
        let mut firsts = Vec::new();
        for seed in 0..9_u8 {
            let artifact = vec![seed; MAX_PROGRAM_BYTES as usize];
            let pieces = split_into_pieces(&artifact).unwrap();
            wanted.insert(pieces[0].content_hash());
            firsts.push(pieces[0].clone());
        }
        assert_eq!(store.absorb(&firsts, &wanted), Vec::<Hash>::new());
        assert_eq!(store.status().assembling.len(), 8);
    }

    #[test]
    fn persisted_artifacts_round_trip_and_publication_streams_a_file() {
        let dir = std::env::temp_dir().join(format!("neutrino-programs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = ProgramStore::open(&dir).unwrap();
        let artifact = vec![b'\0', b'a', b's', b'm', 1, 2, 3];
        let hash = content_hash(&artifact).unwrap();
        assert_eq!(
            store.absorb(&split_into_pieces(&artifact).unwrap(), &wanted(&artifact)),
            vec![hash]
        );
        // Completion alone never touches disk; only installation persists.
        assert_eq!(store.persisted(), Vec::<(Hash, Vec<u8>)>::new());
        store.persist(&hash, &artifact);
        store.mark_installed(&hash);
        assert_eq!(store.persisted(), vec![(hash, artifact.clone())]);
        assert_eq!(ArtifactKind::of(&artifact), ArtifactKind::Wasm);
        // Publication: a 3-piece file yields two pieces per block.
        let file: Vec<u8> = vec![9; MAX_PROGRAM_PIECE_BYTES * 2 + 10];
        fs::write(dir.join("publish").join("upgrade.elf"), &file).unwrap();
        let first = store.next_pieces(2);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].content_hash(), content_hash(&file).unwrap());
        assert_eq!(store.status().publishing.map(|p| p.1), Some(2));
        let last = store.next_pieces(2);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].bytes.len(), 10);
        assert_eq!(store.next_pieces(2), Vec::<ProgramPiece>::new());
        assert!(dir.join("published").join("upgrade.elf").exists());
        let rebuilt = ProgramStore::in_memory();
        let mut all = first;
        all.extend(last);
        assert_eq!(
            rebuilt.absorb(&all, &wanted(&file)),
            vec![content_hash(&file).unwrap()]
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
