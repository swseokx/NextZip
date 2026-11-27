//! File creation cost by API: replicate a tree's files (same relative paths
//! and sizes) below an output folder with N threads.
//!
//! `cargo run --release -p nz-sys --example fsbench -- <src> <out> [threads]`
//! (`CAP=<n>`: most files of one folder per task in the `+dir` variants)
//!
//! Variants: `std` = `File::create` + write, `rel` = `NtCreateFile` relative
//! to an open folder handle, `+time` = set the modification time, `+dir` =
//! one task per folder run instead of one per file, `+blk` = equal
//! contiguous blocks per thread, `+alloc` = allocation size at create.
//!
//! perf-4 (mixed set, 1,444 files, 105 MB, 12 threads, Defender-excluded
//! folder): one task per file 200-230 ms, per folder run 155-175 ms; setting
//! the time costs 20-30 ms either way; `rel` and `+alloc` gained nothing.
//! The real extractor already gets folder locality from Rayon's contiguous
//! splits, so per-folder tasks did not speed it up.

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime};

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut c_void,
        object_name: *const UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_qos: *mut c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: usize,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            h: *mut *mut c_void,
            access: u32,
            oa: *const ObjectAttributes,
            iosb: *mut IoStatusBlock,
            alloc: *const i64,
            attrs: u32,
            share: u32,
            disp: u32,
            opts: u32,
            ea: *mut c_void,
            ealen: u32,
        ) -> i32;
    }

    fn walk(dir: &Path, rel: &Path, out: &mut Vec<(PathBuf, u64)>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let t = e.file_type().unwrap();
            let r = rel.join(e.file_name());
            if t.is_dir() {
                walk(&e.path(), &r, out);
            } else {
                out.push((r, e.metadata().unwrap().len()));
            }
        }
    }

    fn create_rel(root: &OwnedHandle, name: &[u16], alloc: Option<i64>) -> std::fs::File {
        let mut buf = name.to_vec();
        let us = UnicodeString {
            length: (buf.len() * 2) as u16,
            maximum_length: (buf.len() * 2) as u16,
            buffer: buf.as_mut_ptr(),
        };
        let oa = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: root.as_raw_handle(),
            object_name: &us,
            attributes: 0x40,
            security_descriptor: std::ptr::null_mut(),
            security_qos: std::ptr::null_mut(),
        };
        let mut h = std::ptr::null_mut();
        let mut io = IoStatusBlock {
            status: 0,
            information: 0,
        };
        let a = alloc.unwrap_or(0);
        // SAFETY: all pointers are valid for the call.
        let st = unsafe {
            NtCreateFile(
                &mut h,
                0x4000_0000 | 0x0010_0000 | 0x0100,
                &oa,
                &mut io,
                if alloc.is_some() {
                    &a
                } else {
                    std::ptr::null()
                },
                0x80,
                7,
                5,
                0x40 | 0x20,
                std::ptr::null_mut(),
                0,
            )
        };
        assert!(st >= 0, "NtCreateFile {st:#x}");
        // SAFETY: h is a fresh owned file handle.
        unsafe { std::fs::File::from_raw_handle(h) }
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().collect();
        let src = PathBuf::from(&a[1]);
        let out = PathBuf::from(&a[2]);
        let threads: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(12);
        let mut files = Vec::new();
        walk(&src, Path::new(""), &mut files);
        let max = files.iter().map(|f| f.1).max().unwrap_or(0) as usize;
        let zeros = vec![0x5au8; max];
        let mtime = SystemTime::now() - Duration::from_secs(86400 * 30);
        let variants = [
            "std",
            "std+time",
            "std+time+dir",
            "std+time+blk",
            "rel+time+dir",
            "rel+alloc+time+dir",
        ];
        // Directory runs: files of one folder are consecutive in walk order.
        let cap: usize = std::env::var("CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX);
        let mut runs: Vec<(usize, usize)> = Vec::new();
        for (i, f) in files.iter().enumerate() {
            match runs.last_mut() {
                Some(r) if files[r.0].0.parent() == f.0.parent() && i - r.0 < cap => r.1 = i + 1,
                _ => runs.push((i, i + 1)),
            }
        }
        let base = out.clone();
        for round in 0..4 {
            for v in variants {
                let out = base.join(format!("r{round}{}", v.replace('+', "_")));
                let mut dirs: Vec<PathBuf> = files
                    .iter()
                    .filter_map(|f| f.0.parent().map(Path::to_path_buf))
                    .collect();
                dirs.sort();
                dirs.dedup();
                let mut handles: HashMap<PathBuf, OwnedHandle> = HashMap::new();
                for d in &dirs {
                    std::fs::create_dir_all(out.join(d)).unwrap();
                    use std::os::windows::fs::OpenOptionsExt;
                    let h = std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(0x0200_0000)
                        .open(out.join(d))
                        .unwrap();
                    handles.insert(d.clone(), OwnedHandle::from(h));
                }
                std::thread::sleep(Duration::from_millis(500));
                let next = AtomicUsize::new(0);
                let tids = AtomicUsize::new(0);
                let t = Instant::now();
                std::thread::scope(|s| {
                    for _ in 0..threads {
                        s.spawn(|| {
                            let tid = tids.fetch_add(1, Ordering::Relaxed);
                            let mut todo: Vec<usize> = Vec::new();
                            let mut k = 0usize;
                            loop {
                                let i = if v.contains("blk") {
                                    let per = files.len().div_ceil(threads);
                                    let i = tid * per + k;
                                    k += 1;
                                    if k > per || i >= files.len() {
                                        break;
                                    }
                                    i
                                } else if v.contains("dir") {
                                    if todo.is_empty() {
                                        let r = next.fetch_add(1, Ordering::Relaxed);
                                        if r >= runs.len() {
                                            break;
                                        }
                                        todo = (runs[r].0..runs[r].1).rev().collect();
                                    }
                                    todo.pop().unwrap()
                                } else {
                                    let i = next.fetch_add(1, Ordering::Relaxed);
                                    if i >= files.len() {
                                        break;
                                    }
                                    i
                                };
                                let (rel, size) = &files[i];
                                let data = &zeros[..*size as usize];
                                let mut f = if v.starts_with("std") {
                                    std::fs::File::create(out.join(rel)).unwrap()
                                } else {
                                    let parent = rel.parent().unwrap();
                                    let name: Vec<u16> =
                                        rel.file_name().unwrap().encode_wide().collect();
                                    let alloc = v.contains("alloc").then_some(*size as i64);
                                    create_rel(&handles[parent], &name, alloc)
                                };
                                f.write_all(data).unwrap();
                                if v.contains("time") {
                                    f.set_modified(mtime).unwrap();
                                }
                            }
                        });
                    }
                });
                if round > 0 {
                    println!(
                        "{v:<16} {:7.1} ms ({} files)",
                        t.elapsed().as_secs_f64() * 1e3,
                        files.len()
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}

fn main() {
    #[cfg(windows)]
    imp::main();
}
