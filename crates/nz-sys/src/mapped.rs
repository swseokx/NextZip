//! Writable memory mapping of an output file.
//!
//! Writing a large output through `WriteFile` copies every byte into the
//! system cache on one thread (measured: about 4.5 GB/s on this project's
//! test machine). Mapping the file instead lets several threads fill disjoint
//! parts of it at once (about 9 GB/s with 12 threads): each page is
//! zero-filled on first touch and handed to the cache manager when its view is
//! unmapped. A single thread filling fresh pages is slower than `WriteFile`,
//! so this only pays off when the copy is spread over threads.
//!
//! A [`FileMapping`] covers the whole file; [`FileMapping::view`] maps one
//! window of it. Views are unmapped on drop, which moves their pages out of
//! the process working set, so mapping a large file window by window keeps
//! resident memory bounded.

use std::fs::File;
use std::io;

/// Allocation granularity that view offsets must be a multiple of
/// (64 KiB on Windows).
pub const VIEW_ALIGN: u64 = 64 << 10;

/// Whether [`FileMapping`] is implemented on this system.
pub const MAPPING_SUPPORTED: bool = cfg!(windows);

/// A writable mapping of a file. Creating it sets the file's length to `len`
/// (a longer file is not shortened by the mapping; callers that need that
/// call `set_len` after dropping the mapping and its views).
pub struct FileMapping {
    inner: imp::Mapping,
    len: u64,
}

impl FileMapping {
    /// Map `file` (opened for reading and writing) with length `len > 0`.
    pub fn new(file: &File, len: u64) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot map an empty file",
            ));
        }
        Ok(Self {
            inner: imp::Mapping::new(file, len)?,
            len,
        })
    }

    /// Mapped file length.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Always false (an empty mapping cannot be created).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Map `len > 0` bytes at `offset` (a multiple of [`VIEW_ALIGN`]) for
    /// writing. The range must lie inside the mapping.
    pub fn view(&self, offset: u64, len: usize) -> io::Result<MappedView> {
        if !offset.is_multiple_of(VIEW_ALIGN)
            || len == 0
            || offset
                .checked_add(len as u64)
                .is_none_or(|end| end > self.len)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "view outside the mapping or misaligned",
            ));
        }
        Ok(MappedView {
            inner: self.inner.view(offset, len)?,
        })
    }
}

/// One mapped window of a [`FileMapping`]. Disjoint parts of
/// [`MappedView::as_mut_slice`] may be filled from several threads (split it
/// with `split_at_mut` / `chunks_mut`).
pub struct MappedView {
    inner: imp::View,
}

impl MappedView {
    /// The mapped bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.slice()
    }

    /// Unmap, reporting any error (dropping ignores it).
    pub fn finish(mut self) -> io::Result<()> {
        self.inner.close()
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
        PAGE_READWRITE, UnmapViewOfFile,
    };

    pub struct Mapping {
        map: HANDLE,
    }

    // SAFETY: a mapping handle may be used from any thread.
    unsafe impl Send for Mapping {}
    // SAFETY: as above; `MapViewOfFile` is thread-safe.
    unsafe impl Sync for Mapping {}

    impl Mapping {
        pub fn new(file: &File, len: u64) -> io::Result<Self> {
            // SAFETY: the handle is a live file handle owned by `file`; a
            // mapping with a maximum size larger than the file extends it.
            let map = unsafe {
                CreateFileMappingW(
                    file.as_raw_handle() as HANDLE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    (len >> 32) as u32,
                    len as u32,
                    std::ptr::null(),
                )
            };
            if map.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { map })
        }

        pub fn view(&self, offset: u64, len: usize) -> io::Result<View> {
            // SAFETY: `map` is a live mapping handle; the caller checked that
            // the range is aligned and inside the mapping.
            let v = unsafe {
                MapViewOfFile(
                    self.map,
                    FILE_MAP_WRITE,
                    (offset >> 32) as u32,
                    offset as u32,
                    len,
                )
            };
            if v.Value.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(View {
                ptr: v.Value.cast(),
                len,
            })
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: `map` is the mapping handle this value owns. Views keep
            // the section alive on their own after the handle is closed.
            unsafe { CloseHandle(self.map) };
        }
    }

    pub struct View {
        ptr: *mut u8,
        len: usize,
    }

    // SAFETY: the view is plain memory owned by this value; access goes
    // through `&mut self`, so the borrow rules prevent data races.
    unsafe impl Send for View {}
    // SAFETY: as above; `&View` exposes no access to the bytes.
    unsafe impl Sync for View {}

    impl View {
        pub fn slice(&mut self) -> &mut [u8] {
            if self.ptr.is_null() {
                return &mut [];
            }
            // SAFETY: `ptr` points to `len` mapped, writable bytes that stay
            // mapped until `close`; `&mut self` makes the slice exclusive.
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }

        pub fn close(&mut self) -> io::Result<()> {
            if self.ptr.is_null() {
                return Ok(());
            }
            let addr = MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.ptr.cast(),
            };
            self.ptr = std::ptr::null_mut();
            // SAFETY: `addr` is the base address returned by MapViewOfFile,
            // unmapped once.
            if unsafe { UnmapViewOfFile(addr) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for View {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::fs::File;
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "file mapping is not implemented on this system",
        )
    }

    pub struct Mapping;

    impl Mapping {
        pub fn new(_file: &File, _len: u64) -> io::Result<Self> {
            Err(unsupported())
        }
        pub fn view(&self, _offset: u64, _len: usize) -> io::Result<View> {
            Err(unsupported())
        }
    }

    pub struct View;

    impl View {
        pub fn slice(&mut self) -> &mut [u8] {
            &mut []
        }
        pub fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn mapped_views_reach_the_file() {
        let dir = std::env::temp_dir().join(format!("nzsys-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.bin");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        let len = 3 * VIEW_ALIGN + 1234;
        let m = FileMapping::new(&f, len).unwrap();
        assert!(m.view(1, 10).is_err());
        assert!(m.view(0, len as usize + 1).is_err());
        let mut a = m.view(0, 2 * VIEW_ALIGN as usize).unwrap();
        let (x, y) = a.as_mut_slice().split_at_mut(1000);
        std::thread::scope(|s| {
            s.spawn(|| x.fill(1));
            s.spawn(|| y.fill(2));
        });
        a.finish().unwrap();
        let mut b = m
            .view(2 * VIEW_ALIGN, (len - 2 * VIEW_ALIGN) as usize)
            .unwrap();
        b.as_mut_slice().fill(3);
        drop(b);
        drop(m);
        // Shrinking works once the mapping is gone.
        f.set_len(len - 4).unwrap();
        drop(f);
        let back = std::fs::read(&p).unwrap();
        assert_eq!(back.len() as u64, len - 4);
        assert!(back[..1000].iter().all(|&v| v == 1));
        assert!(back[1000..2 * VIEW_ALIGN as usize].iter().all(|&v| v == 2));
        assert!(back[2 * VIEW_ALIGN as usize..].iter().all(|&v| v == 3));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
