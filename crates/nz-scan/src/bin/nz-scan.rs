//! `nz-scan.exe`: the AMSI scanner process (see `nz_scan`).

fn main() {
    std::process::exit(nz_scan::child_main());
}
