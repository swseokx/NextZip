//! Print the folder / coder layout of a 7z archive.
//!
//! `cargo run --release -p nz-core --example sevenz_info -- <archive.7z>`

use nz_core::sevenz::open;

fn method(id: &[u8]) -> String {
    match id {
        [0x00] => "Copy".into(),
        [0x21] => "LZMA2".into(),
        [0x03, 0x01, 0x01] => "LZMA".into(),
        [0x03, 0x03, 0x01, 0x03] => "BCJ".into(),
        [0x03, 0x03, 0x01, 0x1B] => "BCJ2".into(),
        [0x04, 0x01, 0x08] => "Deflate".into(),
        [0x04, 0x01, 0x09] => "Deflate64".into(),
        [0x04, 0x02, 0x02] => "BZip2".into(),
        [0x03, 0x04, 0x01] => "PPMD".into(),
        [0x04, 0xF7, 0x11, 0x01] => "ZSTD".into(),
        [0x04, 0xF7, 0x11, 0x02] => "Brotli".into(),
        [0x04, 0xF7, 0x11, 0x04] => "LZ4".into(),
        [0x04, 0xF7, 0x11, 0x05] => "LZ5".into(),
        [0x04, 0xF7, 0x11, 0x06] => "Lizard".into(),
        [0x06, 0xF1, 0x07, 0x01] => "AES".into(),
        _ => format!("{id:02X?}"),
    }
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("usage: sevenz_info <archive.7z>");
    let a = open(&std::fs::File::open(path)?)?;
    let folders = a.folders();
    println!("{} items, {} folders", a.items.len(), folders.len());
    for (i, (f, packed, unpacked, files)) in folders.iter().enumerate() {
        let chain: Vec<String> = f
            .coders
            .iter()
            .map(|c| format!("{} props={:02X?}", method(&c.id), c.props))
            .collect();
        println!(
            "folder {i}: {files} files, {unpacked} -> {packed} ({:.2}%), coders [{}]",
            *packed as f64 * 100.0 / (*unpacked).max(1) as f64,
            chain.join(", ")
        );
    }
    Ok(())
}
