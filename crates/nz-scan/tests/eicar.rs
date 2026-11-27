//! AMSI end to end with the EICAR antivirus test string (harmless by
//! design: every engine reports it so detection paths can be tested).
//! The string is assembled at run time so no file in the repository
//! contains it (Defender would quarantine such a file).

/// The 68-byte EICAR test string.
pub fn eicar() -> Vec<u8> {
    let parts = [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!$H+H*",
    ];
    parts.concat().into_bytes()
}

fn scanner() -> Option<nz_scan::Scanner> {
    match nz_scan::Scanner::start() {
        Ok(s) => Some(s),
        Err(e) if nz_scan::is_unavailable(&e) && std::env::var_os("NZ_AMSI_REQUIRED").is_none() => {
            eprintln!("skipped: {e:#}");
            None
        }
        Err(e) => panic!("{e:#}"),
    }
}

#[test]
#[ignore = "raises a Defender alert; run with --ignored"]
fn eicar_is_detected() {
    let Some(s) = scanner() else { return };
    let v = s.scan("eicar.com", &eicar()).unwrap();
    assert_eq!(v, nz_scan::Verdict::Detected);
}

#[test]
fn clean_data_is_clean() {
    let Some(s) = scanner() else { return };
    let v = s.scan("hello.txt", b"hello, world\n").unwrap();
    assert_eq!(v, nz_scan::Verdict::Clean);
}

/// EICAR straddling the boundary of two scan windows is still found
/// (the windows overlap).
#[test]
#[ignore = "raises a Defender alert; run with --ignored"]
fn eicar_across_window_boundary() {
    let Some(s) = scanner() else { return };
    let mut data = vec![b' '; nz_scan::WINDOW - 30];
    data.extend_from_slice(&eicar());
    data.extend(std::iter::repeat_n(b' ', 1000));
    let mut scan = s.begin("big.bin").unwrap();
    for c in data.chunks(1 << 20) {
        scan.data(c).unwrap();
    }
    assert_eq!(scan.end().unwrap(), nz_scan::Verdict::Detected);
}

/// The pool serves several threads and recovers after an abandoned item.
#[test]
fn pool_is_reusable_across_threads() {
    let Some(s) = scanner() else { return };
    drop(s.begin("abandoned").unwrap());
    std::thread::scope(|sc| {
        for i in 0..8 {
            let s = &s;
            sc.spawn(move || {
                let v = s.scan(&format!("f{i}.txt"), b"plain text").unwrap();
                assert_eq!(v, nz_scan::Verdict::Clean);
            });
        }
    });
}
