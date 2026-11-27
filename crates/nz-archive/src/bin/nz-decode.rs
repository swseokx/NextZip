//! NextZip isolated decoder process. Started by `nz-archive` for RAR and
//! the legacy/rare formats; it locks itself down before reading anything
//! (see `nz_archive::isolated`). With `--scan` it is the AMSI scanner
//! process instead (see `nz_scan`). Not meant to be run by hand.

fn main() {
    if std::env::args_os().nth(1).is_some_and(|a| a == "--scan") {
        std::process::exit(nz_scan::child_main());
    }
    std::process::exit(nz_archive::isolated::child_main());
}
