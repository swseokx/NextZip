// Packs the files to install into OUT_DIR/payload.bin and embeds the
// application manifest (asInvoker: without it Windows' installer detection
// would ask for elevation because the file name contains "setup").
//
// NZ_SETUP_PAYLOAD=<dir> names the folder holding the release binaries
// (`packaging/build-installer.ps1` sets it). Without it the payload is
// empty: the binary builds and its tests run, but it refuses to install.
//
// payload.bin: u32 count, then per file: u16 name length, UTF-8 name,
// u64 size, u64 compressed size, zstd frame.

use std::io::Write;
use std::path::Path;

const FILES: [&str; 6] = [
    "nextzip.exe",
    "nz.exe",
    "nz-decode.exe",
    "nextzip_shell.dll",
    "nz-sfx-x64.exe",
    "nz-sfx-arm64.exe",
];

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=nextzip-setup.manifest");
    println!("cargo:rerun-if-env-changed=NZ_SETUP_PAYLOAD");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let manifest = Path::new(&dir).join("nextzip-setup.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }

    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("payload.bin");
    let mut buf = Vec::new();
    match std::env::var_os("NZ_SETUP_PAYLOAD") {
        Some(src) => {
            let src = Path::new(&src);
            buf.extend_from_slice(&(FILES.len() as u32).to_le_bytes());
            for name in FILES {
                let p = src.join(name);
                println!("cargo:rerun-if-changed={}", p.display());
                let data = std::fs::read(&p).unwrap_or_else(|e| {
                    panic!("NZ_SETUP_PAYLOAD: cannot read {}: {e}", p.display())
                });
                let packed = zstd::bulk::compress(&data, 19).expect("zstd");
                buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
                buf.extend_from_slice(name.as_bytes());
                buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
                buf.extend_from_slice(&(packed.len() as u64).to_le_bytes());
                buf.extend_from_slice(&packed);
            }
        }
        None => buf.extend_from_slice(&0u32.to_le_bytes()),
    }
    std::fs::File::create(&out)
        .and_then(|mut f| f.write_all(&buf))
        .expect("write payload.bin");
}
