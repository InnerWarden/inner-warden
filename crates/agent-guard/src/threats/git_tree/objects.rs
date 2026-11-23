//! What a repository tracks, read from its own files: the paths in its
//! index, and the tree of a commit a name points at. git itself is not run:
//! a repository's config can make git run a program (`core.fsmonitor`, the
//! fetch of a partial clone), and the guard must not run one to judge a line.
//!
//! Read: the index (versions 2 to 4), loose references and `packed-refs`,
//! loose objects and packs (version 2 index, deltas by offset and by name),
//! alternates one level deep. Not read, and so not known: a repository in
//! SHA-256 or with a reftable, a name with `~`, `^`, `:` or `@{`, an object
//! past [`OBJECT_BYTES`].

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Largest index read.
const INDEX_BYTES: u64 = 64 << 20;
/// Largest object read, once inflated.
const OBJECT_BYTES: usize = 64 << 20;
/// How many deltas one object is rebuilt through.
const DELTA_DEPTH: usize = 64;
/// How many objects one repository is asked for.
const OBJECTS_READ: usize = 1024;
/// How many references one name is followed through.
const REF_DEPTH: usize = 8;
/// How many alternate object stores are read.
const ALTERNATES: usize = 8;
/// Largest reference file or `packed-refs` read.
const REFS_BYTES: u64 = 16 << 20;
/// The length of an object name (SHA-1).
const OID: usize = 20;

type Oid = [u8; OID];

/// Whether `name`, a path in the repository, is one of `targets`, below
/// one, or above one (a file where a target's folder would be). An empty
/// target is the whole tree. Lowercase, as the targets are.
pub(super) fn hits(name: &str, targets: &[String]) -> bool {
    let name = name.to_lowercase();
    let name = name.trim_end_matches('/');
    targets.iter().any(|target| {
        target.is_empty()
            || name == target
            || name
                .strip_prefix(target.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
            || target
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// A repository's files: its own folder (`HEAD`, the index) and the common
/// one (references, objects), which differ for a linked work tree.
pub(super) struct Repo {
    git_dir: PathBuf,
    common: PathBuf,
    stores: Vec<PathBuf>,
    asked: std::cell::Cell<usize>,
}

impl Repo {
    /// The repository at `git_dir`; `None` when it is in a form not read.
    pub(super) fn open(git_dir: &Path) -> Option<Repo> {
        let common = match read_small(&git_dir.join("commondir")) {
            Some(text) => {
                let named = PathBuf::from(String::from_utf8_lossy(&text).trim());
                if named.is_absolute() {
                    named
                } else {
                    git_dir.join(named)
                }
            }
            None => git_dir.to_path_buf(),
        };
        if let Some(config) = read_small(&common.join("config")) {
            let config = String::from_utf8_lossy(&config).to_ascii_lowercase();
            if config.contains("sha256") || config.contains("reftable") {
                return None;
            }
        }
        if common.join("reftable").exists() {
            return None;
        }
        let objects = common.join("objects");
        let mut stores = vec![objects.clone()];
        if let Some(text) = read_small(&objects.join("info/alternates")) {
            for line in String::from_utf8_lossy(&text).lines().take(ALTERNATES) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let store = PathBuf::from(line);
                stores.push(if store.is_absolute() {
                    store
                } else {
                    objects.join(store)
                });
            }
        }
        Some(Repo {
            git_dir: git_dir.to_path_buf(),
            common,
            stores,
            asked: std::cell::Cell::new(0),
        })
    }

    /// Whether the repository's index holds a path of `targets`; `None`
    /// when it cannot be read.
    pub(super) fn index_holds(&self, targets: &[String]) -> Option<bool> {
        index_holds(&self.git_dir.join("index"), targets)
    }

    /// Whether the tree of the commit `rev` names holds a path of
    /// `targets`; `None` when the name or a tree cannot be read.
    /// A name that points at nothing holds nothing: git refuses it.
    pub(super) fn rev_holds(&self, rev: &str, targets: &[String]) -> Option<bool> {
        let Some(mut oid) = self.resolve(rev)? else {
            return Some(false);
        };
        let mut tree = None;
        for _ in 0..REF_DEPTH {
            let (kind, data) = self.object(&oid, 0)?;
            match kind {
                Kind::Tree => {
                    tree = Some(data);
                    break;
                }
                Kind::Commit => oid = header_oid(&data, b"tree ")?,
                Kind::Tag => oid = header_oid(&data, b"object ")?,
                Kind::Blob => return None,
            }
        }
        let root = tree?;
        let mut holds = false;
        for target in targets {
            if target.is_empty() {
                if !tree_entries(&root)?.is_empty() {
                    return Some(true);
                }
                continue;
            }
            if self.tree_holds(&root, target)? {
                holds = true;
                break;
            }
        }
        Some(holds)
    }

    /// Whether `root` holds the path `target`, or a file where one of its
    /// folders would be.
    fn tree_holds(&self, root: &[u8], target: &str) -> Option<bool> {
        let parts: Vec<&str> = target.split('/').filter(|part| !part.is_empty()).collect();
        let mut data = root.to_vec();
        for (at, part) in parts.iter().enumerate() {
            let entries = tree_entries(&data)?;
            let Some((mode, _, oid)) = entries
                .into_iter()
                .find(|(_, name, _)| name.to_lowercase() == *part)
            else {
                return Some(false);
            };
            if at + 1 == parts.len() || mode != "40000" {
                return Some(true);
            }
            let (kind, next) = self.object(&oid, 0)?;
            if kind != Kind::Tree {
                return None;
            }
            data = next;
        }
        Some(true)
    }

    /// The object `name` points at: a full object name, `HEAD` (`@`), a
    /// reference, a branch, a tag or a remote branch, as git looks them up.
    /// `Some(None)` when it points at nothing; `None` when what it points
    /// at is not known here: a name git reads in a way not read here (an
    /// abbreviated object name, `describe` output, `~`, `^`, `@{`), or a
    /// branch only a remote has, which `checkout` and `switch` make.
    fn resolve(&self, name: &str) -> Option<Option<Oid>> {
        let name = if name == "@" { "HEAD" } else { name };
        if let Some(oid) = hex_oid(name) {
            return Some(Some(oid));
        }
        if name.is_empty()
            || name.starts_with(['-', '/', '.'])
            || name.contains(['~', '^', ':', '@', '\\', '?', '*', '[', ' '])
            || name.contains("..")
            || (name.len() >= 4 && name.bytes().all(|b| b.is_ascii_hexdigit()))
            || name.rsplit_once("-g").is_some_and(|(_, hex)| {
                hex.len() >= 4 && hex.bytes().all(|b| b.is_ascii_hexdigit())
            })
        {
            return None;
        }
        let mut candidates = Vec::new();
        if name.starts_with("refs/") || name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            candidates.push(name.to_string());
        }
        for prefix in ["refs/", "refs/tags/", "refs/heads/", "refs/remotes/"] {
            candidates.push(format!("{prefix}{name}"));
        }
        candidates.push(format!("refs/remotes/{name}/HEAD"));
        for candidate in candidates {
            if let Some(oid) = self.reference(&candidate, 0)? {
                return Some(Some(oid));
            }
        }
        if !name.contains('/') && self.a_remote_has(name)? {
            return None;
        }
        Some(None)
    }

    /// Whether a remote has a branch `name` (`refs/remotes/<remote>/<name>`).
    fn a_remote_has(&self, name: &str) -> Option<bool> {
        if let Ok(remotes) = std::fs::read_dir(self.common.join("refs/remotes")) {
            for remote in remotes.flatten() {
                if remote.path().join(name).exists() {
                    return Some(true);
                }
            }
        }
        let suffix = format!("/{name}");
        let Some(packed) = read_small(&self.common.join("packed-refs")) else {
            return Some(false);
        };
        Some(String::from_utf8_lossy(&packed).lines().any(|line| {
            line.split_once(' ').is_some_and(|(_, full)| {
                let full = full.trim();
                full.starts_with("refs/remotes/") && full.ends_with(&suffix)
            })
        }))
    }

    /// The object the reference `full` points at: `Some(None)` when there
    /// is no such reference, `None` when it cannot be read.
    fn reference(&self, full: &str, depth: usize) -> Option<Option<Oid>> {
        if depth > REF_DEPTH {
            return None;
        }
        let own = !full.starts_with("refs/")
            || full.starts_with("refs/worktree/")
            || full.starts_with("refs/bisect/");
        let dir = if own { &self.git_dir } else { &self.common };
        let path = dir.join(full);
        if path.is_file() {
            let text = read_small(&path)?;
            let text = String::from_utf8_lossy(&text);
            let first = text.lines().next().unwrap_or("").trim();
            if let Some(target) = first.strip_prefix("ref:") {
                return self.reference(target.trim(), depth + 1);
            }
            return hex_oid(first.get(..OID * 2)?).map(Some);
        }
        let Some(packed) = read_small(&self.common.join("packed-refs")) else {
            return Some(None);
        };
        for line in String::from_utf8_lossy(&packed).lines() {
            if line.starts_with(['#', '^']) {
                continue;
            }
            if let Some((oid, name)) = line.split_once(' ') {
                if name.trim() == full {
                    return hex_oid(oid).map(Some);
                }
            }
        }
        Some(None)
    }

    /// The object `oid`, loose or in a pack.
    fn object(&self, oid: &Oid, depth: usize) -> Option<(Kind, Vec<u8>)> {
        let asked = self.asked.get() + 1;
        self.asked.set(asked);
        if asked > OBJECTS_READ || depth > DELTA_DEPTH {
            return None;
        }
        let hex = to_hex(oid);
        for store in &self.stores {
            let loose = store.join(&hex[..2]).join(&hex[2..]);
            if let Ok(file) = File::open(&loose) {
                let mut data = Vec::new();
                flate2::read::ZlibDecoder::new(file)
                    .take(OBJECT_BYTES as u64 + 64)
                    .read_to_end(&mut data)
                    .ok()?;
                let nul = data.iter().position(|b| *b == 0)?;
                let header = std::str::from_utf8(&data[..nul]).ok()?;
                let (kind, size) = header.split_once(' ')?;
                let kind = Kind::named(kind)?;
                let size: usize = size.parse().ok()?;
                let body = data.split_off(nul + 1);
                if body.len() != size {
                    return None;
                }
                return Some((kind, body));
            }
        }
        for store in &self.stores {
            let Ok(packs) = std::fs::read_dir(store.join("pack")) else {
                continue;
            };
            for entry in packs.flatten() {
                let idx = entry.path();
                if idx.extension().and_then(|e| e.to_str()) != Some("idx") {
                    continue;
                }
                if let Some(offset) = pack_offset(&idx, oid)? {
                    return self.packed(&idx.with_extension("pack"), offset, depth);
                }
            }
        }
        None
    }

    /// The object at `offset` in the pack `pack`, its deltas applied.
    fn packed(&self, pack: &Path, offset: u64, depth: usize) -> Option<(Kind, Vec<u8>)> {
        if depth > DELTA_DEPTH {
            return None;
        }
        let mut file = File::open(pack).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut reader = BufReader::new(file);
        let mut byte = read_byte(&mut reader)?;
        let kind = (byte >> 4) & 7;
        let mut size = usize::from(byte & 15);
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            byte = read_byte(&mut reader)?;
            size |= usize::from(byte & 0x7f).checked_shl(shift)?;
            shift += 7;
            if shift > 56 {
                return None;
            }
        }
        if size > OBJECT_BYTES {
            return None;
        }
        let base = match kind {
            6 => {
                let mut byte = read_byte(&mut reader)?;
                let mut back = u64::from(byte & 0x7f);
                while byte & 0x80 != 0 {
                    byte = read_byte(&mut reader)?;
                    back = back.checked_add(1)?.checked_mul(128)? | u64::from(byte & 0x7f);
                }
                Some(Base::At(offset.checked_sub(back)?))
            }
            7 => {
                let mut oid = [0u8; OID];
                reader.read_exact(&mut oid).ok()?;
                Some(Base::Named(oid))
            }
            _ => None,
        };
        let data = inflate(&mut reader, size)?;
        match base {
            None => Some((Kind::numbered(kind)?, data)),
            Some(base) => {
                let (kind, source) = match base {
                    Base::At(at) => self.packed(pack, at, depth + 1)?,
                    Base::Named(oid) => self.object(&oid, depth + 1)?,
                };
                Some((kind, apply_delta(&source, &data)?))
            }
        }
    }
}

/// Whether the index file at `path` holds a path of `targets`.
fn index_holds(path: &Path, targets: &[String]) -> Option<bool> {
    let file = File::open(path).ok()?;
    if file.metadata().ok()?.len() > INDEX_BYTES {
        return None;
    }
    let mut data = Vec::new();
    file.take(INDEX_BYTES).read_to_end(&mut data).ok()?;
    if data.get(..4)? != b"DIRC" {
        return None;
    }
    let version = be32(&data, 4)?;
    if !(2..=4).contains(&version) {
        return None;
    }
    let count = be32(&data, 8)? as usize;
    let mut at = 12usize;
    let mut previous: Vec<u8> = Vec::new();
    for _ in 0..count {
        let flags = be16(&data, at + 40 + OID)?;
        let mut name_at = at + 40 + OID + 2;
        if version >= 3 && flags & 0x4000 != 0 {
            name_at += 2;
        }
        let name = if version == 4 {
            let (strip, used) = offset_varint(&data, name_at)?;
            let start = name_at + used;
            let end = start + data.get(start..)?.iter().position(|b| *b == 0)?;
            let keep = previous.len().checked_sub(strip)?;
            let mut name = previous[..keep].to_vec();
            name.extend_from_slice(&data[start..end]);
            at = end + 1;
            name
        } else {
            let end = name_at + data.get(name_at..)?.iter().position(|b| *b == 0)?;
            let name = data[name_at..end].to_vec();
            at += (end - at + 8) & !7;
            name
        };
        if hits(&String::from_utf8_lossy(&name), targets) {
            return Some(true);
        }
        previous = name;
    }
    Some(false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    fn named(name: &str) -> Option<Kind> {
        Some(match name {
            "commit" => Kind::Commit,
            "tree" => Kind::Tree,
            "blob" => Kind::Blob,
            "tag" => Kind::Tag,
            _ => return None,
        })
    }

    fn numbered(number: u8) -> Option<Kind> {
        Some(match number {
            1 => Kind::Commit,
            2 => Kind::Tree,
            3 => Kind::Blob,
            4 => Kind::Tag,
            _ => return None,
        })
    }
}

enum Base {
    At(u64),
    Named(Oid),
}

/// Where `oid` is in the pack whose index is `idx` (version 2):
/// `Some(None)` when it is not there, `None` when the index cannot be read.
fn pack_offset(idx: &Path, oid: &Oid) -> Option<Option<u64>> {
    let mut file = File::open(idx).ok()?;
    let mut head = [0u8; 8 + 256 * 4];
    file.read_exact(&mut head).ok()?;
    if head[..4] != [0xff, 0x74, 0x4f, 0x63] || be32(&head, 4)? != 2 {
        return None;
    }
    let fan = |at: usize| be32(&head, 8 + at * 4).map(|n| n as u64);
    let total = fan(255)?;
    let first = usize::from(oid[0]);
    let mut low = if first == 0 { 0 } else { fan(first - 1)? };
    let mut high = fan(first)?;
    let names_at = 8 + 256 * 4;
    let mut name = [0u8; OID];
    let mut found = None;
    while low < high {
        let mid = low + (high - low) / 2;
        file.seek(SeekFrom::Start(names_at + mid * OID as u64))
            .ok()?;
        file.read_exact(&mut name).ok()?;
        match name.cmp(oid) {
            std::cmp::Ordering::Equal => {
                found = Some(mid);
                break;
            }
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
        }
    }
    let Some(index) = found else {
        return Some(None);
    };
    let offsets_at = names_at + total * (OID as u64 + 4);
    let mut word = [0u8; 4];
    file.seek(SeekFrom::Start(offsets_at + index * 4)).ok()?;
    file.read_exact(&mut word).ok()?;
    let small = u32::from_be_bytes(word);
    if small & 0x8000_0000 == 0 {
        return Some(Some(u64::from(small)));
    }
    let large = u64::from(small & 0x7fff_ffff);
    let mut long = [0u8; 8];
    file.seek(SeekFrom::Start(offsets_at + total * 4 + large * 8))
        .ok()?;
    file.read_exact(&mut long).ok()?;
    Some(Some(u64::from_be_bytes(long)))
}

/// `size` bytes inflated from where `reader` is.
fn inflate(reader: &mut BufReader<File>, size: usize) -> Option<Vec<u8>> {
    let mut data = Vec::with_capacity(size.min(1 << 20));
    flate2::bufread::ZlibDecoder::new(reader)
        .take(size as u64 + 1)
        .read_to_end(&mut data)
        .ok()?;
    (data.len() == size).then_some(data)
}

/// `delta` applied to `base`.
fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let (source, mut at) = size_varint(delta, 0)?;
    if source != base.len() {
        return None;
    }
    let (target, used) = size_varint(delta, at)?;
    at += used;
    if target > OBJECT_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(target);
    while at < delta.len() {
        let op = delta[at];
        at += 1;
        if op & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    offset |= usize::from(*delta.get(at)?) << (8 * bit);
                    at += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    size |= usize::from(*delta.get(at)?) << (8 * bit);
                    at += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            out.extend_from_slice(base.get(offset..offset.checked_add(size)?)?);
        } else if op != 0 {
            let size = usize::from(op);
            out.extend_from_slice(delta.get(at..at + size)?);
            at += size;
        } else {
            return None;
        }
        if out.len() > target {
            return None;
        }
    }
    (out.len() == target).then_some(out)
}

/// A tree's entries: mode, name and object.
fn tree_entries(data: &[u8]) -> Option<Vec<(String, String, Oid)>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let space = at + data[at..].iter().position(|b| *b == b' ')?;
        let nul = space + data[space..].iter().position(|b| *b == 0)?;
        let mode = String::from_utf8_lossy(&data[at..space]).into_owned();
        let name = String::from_utf8_lossy(&data[space + 1..nul]).into_owned();
        let oid: Oid = data.get(nul + 1..nul + 1 + OID)?.try_into().ok()?;
        out.push((mode, name, oid));
        at = nul + 1 + OID;
    }
    Some(out)
}

/// The object a commit or tag names on its `field` line.
fn header_oid(data: &[u8], field: &[u8]) -> Option<Oid> {
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(hex) = line.strip_prefix(field) {
            return hex_oid(std::str::from_utf8(hex).ok()?.trim());
        }
    }
    None
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    let file = File::open(path).ok()?;
    let mut data = Vec::new();
    file.take(REFS_BYTES).read_to_end(&mut data).ok()?;
    Some(data)
}

fn read_byte(reader: &mut BufReader<File>) -> Option<u8> {
    let byte = *reader.fill_buf().ok()?.first()?;
    reader.consume(1);
    Some(byte)
}

fn hex_oid(text: &str) -> Option<Oid> {
    if text.len() != OID * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut oid = [0u8; OID];
    for (at, byte) in oid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).ok()?;
    }
    Some(oid)
}

fn to_hex(oid: &Oid) -> String {
    oid.iter().map(|b| format!("{b:02x}")).collect()
}

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

/// The varint of an index entry's name (version 4) and of a delta's base
/// offset: each more byte adds one before the shift.
fn offset_varint(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut used = 0usize;
    let mut byte = *data.get(at)?;
    used += 1;
    let mut value = usize::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *data.get(at + used)?;
        used += 1;
        value = value.checked_add(1)?.checked_mul(128)? | usize::from(byte & 0x7f);
    }
    Some((value, used))
}

/// The little-endian varint of a delta's sizes.
fn size_varint(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut shift = 0u32;
    let mut used = 0usize;
    loop {
        let byte = *data.get(at + used)?;
        used += 1;
        value |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some((value, used));
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}
