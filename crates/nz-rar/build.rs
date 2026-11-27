fn main() {
    // unrar_sys does not declare the Win32 libraries UnRAR uses (registry,
    // token privileges, CryptoAPI random, ACLs).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=advapi32");
    }
}
