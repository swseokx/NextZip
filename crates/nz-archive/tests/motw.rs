//! Mark-of-the-Web propagation (spec 9): files extracted from an archive
//! marked as downloaded from the Internet carry the mark too.
#![cfg(windows)]

use std::path::Path;

/// A ZIP with two files (a directory source adds its contents).
fn zip_bytes() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("d").join("b.txt"), b"beta").unwrap();
    let out = dir.path().join("t.zip");
    let opt = nz_core::CompressOptions::new(nz_core::Format::Zip, 1, 1);
    nz_core::compress(&[src.join("a.txt"), src.join("d")], &out, &opt).unwrap();
    std::fs::read(out).unwrap()
}

fn zone(file: &Path) -> Option<String> {
    let mut ads = file.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    std::fs::read_to_string(ads).ok()
}

fn extract_with_zone(zone_text: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let arc = dir.path().join("t.zip");
    std::fs::write(&arc, zip_bytes()).unwrap();
    if let Some(z) = zone_text {
        let mut ads = arc.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        std::fs::write(ads, z).unwrap();
    }
    let out = dir.path().join("out");
    nz_archive::extract(&arc, &out, &nz_archive::Options::default(), None).unwrap();
    (dir, out)
}

#[test]
fn internet_zone_is_propagated() {
    let (_d, out) = extract_with_zone(Some(
        "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/t.zip\r\n",
    ));
    for f in [out.join("a.txt"), out.join("b.txt")] {
        let z = zone(&f).unwrap_or_else(|| panic!("no mark on {}", f.display()));
        assert!(z.contains("ZoneId=3"), "{z}");
        assert!(z.contains("t.zip"), "{z}");
    }
}

#[test]
fn local_and_unmarked_archives_add_no_mark() {
    for z in [None, Some("[ZoneTransfer]\r\nZoneId=2\r\n")] {
        let (_d, out) = extract_with_zone(z);
        assert!(zone(&out.join("a.txt")).is_none());
    }
}
