//! Archive members read back out by path, each archive decoded once.
//!
//! A comparison reads the changed members of the same two archives from
//! several places — the changed-line diff, the source differential, the
//! build-macro detectors, evidence. `cleave::extract_member` decodes the whole
//! compressed tarball again for each of those reads, which made xz 5.6.0's
//! 756-entry release take longer than fifteen minutes; [`member`] keeps the
//! last few archives open instead.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// Archives kept open. A comparison reads two at a time, old and new; a
/// tree comparison moves on from one pair to the next, so older ones go.
const OPEN: usize = 4;

/// Open archives, least recently read first. `None` is a file that is no
/// archive, remembered so it is not read again.
type Opened = Vec<(PathBuf, Arc<Option<cleave::ArchiveMembers>>)>;

static ARCHIVES: Mutex<Opened> = Mutex::new(Vec::new());

/// One member of `archive`; `None` when it is absent, nested in an inner
/// archive, or `archive` is no supported archive.
pub(crate) fn member(archive: &Path, member: &str) -> Result<Option<Vec<u8>>> {
    match opened(archive)?.as_ref() {
        Some(members) => members.member(member),
        None => Ok(None),
    }
}

fn opened(archive: &Path) -> Result<Arc<Option<cleave::ArchiveMembers>>> {
    let lock = || ARCHIVES.lock().unwrap_or_else(PoisonError::into_inner);
    let mut archives = lock();
    if let Some(at) = archives.iter().position(|(path, _)| path == archive) {
        let entry = archives.remove(at);
        let members = Arc::clone(&entry.1);
        archives.push(entry);
        drop(archives);
        return Ok(members);
    }
    // Decoded outside the lock: a large tarball takes seconds.
    drop(archives);
    let started = std::time::Instant::now();
    let members = Arc::new(cleave::ArchiveMembers::open(archive)?);
    log::debug!(
        "opened {} for member reads in {:?} (archive: {})",
        archive.display(),
        started.elapsed(),
        members.is_some()
    );
    let mut archives = lock();
    if archives.len() >= OPEN {
        archives.remove(0);
    }
    archives.push((archive.to_path_buf(), Arc::clone(&members)));
    drop(archives);
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::member;

    #[test]
    fn a_member_is_read_from_a_held_archive_and_a_plain_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("pkg.tar");
        let mut tar = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let body = b"module.exports = 1;\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "package/index.js", &body[..])
            .unwrap();
        tar.finish().unwrap();
        drop(tar);
        for _ in 0..2 {
            assert_eq!(
                member(&archive, "package/index.js").unwrap().as_deref(),
                Some(&body[..])
            );
        }
        assert_eq!(member(&archive, "package/absent.js").unwrap(), None);
        let plain = dir.path().join("index.js");
        std::fs::write(&plain, body).unwrap();
        assert_eq!(member(&plain, "index.js").unwrap(), None);
    }
}
