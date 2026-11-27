//! Extract with nz-core's own extractors (no nz-archive layer), for comparing
//! the two ZIP extraction paths. Usage: `xcore <archive> <out_dir>`.
fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let s = nz_core::extract(
        std::path::Path::new(&a[1]),
        std::path::Path::new(&a[2]),
        nz_core::default_threads(),
    )?;
    eprintln!("{} files {} bytes", s.files, s.bytes);
    Ok(())
}
