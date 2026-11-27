// Delay-load the DLLs that only the RAR decoder (unrar, C++) and the
// legacy-archive code pull in. Loading USER32 and the OLE/C++ runtimes at
// process start cost ~3.5 ms on every `nz` run (6.1 -> 9.7 ms start-up after
// the M2 merge), a visible share of a 60 ms ZIP compression (K1). With
// /DELAYLOAD they load on first call instead, i.e. only when such an
// archive is actually opened.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for dll in [
            "USER32.dll",
            "ole32.dll",
            "OLEAUT32.dll",
            "ADVAPI32.dll",
            "MSVCP140.dll",
        ] {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
}
