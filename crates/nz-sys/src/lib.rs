//! OS shim for NextZip.
//!
//! Windows splits machines with more than 64 logical CPUs into *processor
//! groups* of at most 64 CPUs. `GetSystemInfo` (and therefore Rust's
//! `std::thread::available_parallelism`) only reports the CPUs of the calling
//! thread's group, and on Windows 10 / Server 2019 a new thread stays in its
//! process's primary group unless it is moved with `SetThreadGroupAffinity`.
//! This crate exposes exactly the operations the engine needs:
//!
//! * [`processor_groups`]: active logical CPUs per group,
//! * [`logical_cpus`]: `GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)`, and
//! * [`bind_current_thread`]: move the calling thread into one group, and
//! * [`decode_ansi`]: decode bytes in the system ANSI code page (CP949 on
//!   Korean Windows), for archive names written by tools that do not use UTF-8.
//! * [`available_memory`]: free physical memory, for the engine's memory budget.
//! * [`alternate_streams`]: NTFS alternate data streams of a file, for `.nz`.
//! * [`process_peak_memory`]: peak memory of a (finished) child process, for
//!   `nz bench`.
//!
//! * [`FileMapping`]: a writable mapping of an output file, so several threads
//!   (or a decoder) can fill it without a single-threaded `WriteFile` copy.
//!
//! On other systems there is one "group" holding every CPU and binding is a
//! no-op.

/// One processor group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessorGroup {
    /// Group number (0-based).
    pub index: u16,
    /// Active logical CPUs in the group.
    pub active: u32,
    /// Affinity mask of the active CPUs in the group.
    pub mask: u64,
}

/// Mask with the lowest `n` bits set (`n <= 64`).
pub fn low_mask(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

mod mapped;
pub use mapped::{FileMapping, MAPPING_SUPPORTED, MappedView, VIEW_ALIGN};

/// Active processor groups of the machine, in group order. Never empty.
pub fn processor_groups() -> Vec<ProcessorGroup> {
    let groups = imp::processor_groups();
    if groups.is_empty() || groups.iter().all(|g| g.active == 0) {
        let n = std::thread::available_parallelism().map_or(1, |n| n.get()) as u32;
        return vec![ProcessorGroup {
            index: 0,
            active: n,
            mask: low_mask(n),
        }];
    }
    groups
}

/// Total active logical CPUs over all groups
/// (`GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)` on Windows).
pub fn logical_cpus() -> usize {
    match imp::all_processors() {
        Some(n) if n > 0 => n as usize,
        _ => processor_groups().iter().map(|g| g.active as usize).sum(),
    }
}

/// Restrict the calling thread to the CPUs `mask` of processor group `group`.
/// A no-op on systems without processor groups.
pub fn bind_current_thread(group: u16, mask: u64) -> std::io::Result<()> {
    imp::bind_current_thread(group, mask)
}

/// Decode `bytes` in the system ANSI code page (`CP_ACP`). `None` when the
/// bytes are not valid in that code page, and always on non-Windows systems.
pub fn decode_ansi(bytes: &[u8]) -> Option<String> {
    imp::decode_ansi(bytes)
}

/// Physical memory currently available to processes, in bytes
/// (`GlobalMemoryStatusEx().ullAvailPhys`). `None` when unknown.
/// The user's Windows display language (`GetUserDefaultUILanguage`), a
/// LANGID; `None` off Windows.
pub fn ui_language() -> Option<u16> {
    imp::ui_language()
}

pub fn available_memory() -> Option<u64> {
    imp::available_memory()
}

/// Private bytes committed by this process right now (`PagefileUsage`);
/// `None` on failure and on non-Windows systems.
pub fn current_commit() -> Option<u64> {
    imp::current_commit()
}

/// Peak memory of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeakMemory {
    /// Peak working set (resident bytes).
    pub working_set: u64,
    /// Peak private commit (`PeakPagefileUsage`).
    pub commit: u64,
}

/// Peak memory of the process behind `handle` (a process handle with
/// `PROCESS_QUERY_LIMITED_INFORMATION` access, such as the one
/// `std::process::Child` holds; it stays valid after the child exits until the
/// `Child` is dropped). `None` on failure and on non-Windows systems.
#[cfg(windows)]
pub fn process_peak_memory(handle: std::os::windows::io::RawHandle) -> Option<PeakMemory> {
    imp::process_peak_memory(handle)
}

/// Named `$DATA` streams of a file or directory (NTFS alternate data
/// streams), as (name, size) sorted by name; the unnamed main stream is not
/// included. Empty on file systems without streams and on other systems.
pub fn alternate_streams(path: &std::path::Path) -> std::io::Result<Vec<(String, u64)>> {
    imp::alternate_streams(path)
}
#[cfg(windows)]
mod imp {
    use super::{ProcessorGroup, low_mask};
    use windows_sys::Win32::System::SystemInformation::{
        GROUP_AFFINITY, GROUP_RELATIONSHIP, GetLogicalProcessorInformationEx, PROCESSOR_GROUP_INFO,
        RelationGroup, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
    };
    use windows_sys::Win32::System::Threading::{
        ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetActiveProcessorGroupCount,
        GetCurrentThread, SetThreadGroupAffinity,
    };

    pub fn all_processors() -> Option<u32> {
        // SAFETY: plain query without pointers.
        let n = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
        (n > 0).then_some(n)
    }

    pub fn processor_groups() -> Vec<ProcessorGroup> {
        if let Some(g) = groups_from_lpi() {
            return g;
        }
        // Fallback: counts per group, masks assumed contiguous.
        // SAFETY: plain queries without pointers.
        let count = unsafe { GetActiveProcessorGroupCount() };
        (0..count)
            .map(|index| {
                // SAFETY: plain query without pointers.
                let active = unsafe { GetActiveProcessorCount(index) };
                ProcessorGroup {
                    index,
                    active,
                    mask: low_mask(active),
                }
            })
            .collect()
    }

    /// Exact per-group active masks from `GetLogicalProcessorInformationEx(RelationGroup)`.
    fn groups_from_lpi() -> Option<Vec<ProcessorGroup>> {
        let mut len = 0u32;
        // SAFETY: a null buffer with length 0 only asks for the required size.
        unsafe {
            GetLogicalProcessorInformationEx(RelationGroup, std::ptr::null_mut(), &mut len);
        }
        if len == 0 {
            return None;
        }
        // u64 storage keeps the buffer 8-byte aligned for the structures.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ptr = buf
            .as_mut_ptr()
            .cast::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>();
        // SAFETY: `buf` holds at least `len` writable, suitably aligned bytes.
        let ok = unsafe { GetLogicalProcessorInformationEx(RelationGroup, ptr, &mut len) };
        if ok == 0 {
            return None;
        }
        // SAFETY: on success the buffer starts with one RelationGroup record
        // whose `ActiveGroupCount` bounds the trailing `GroupInfo` array
        // (declared with length 1, laid out inline); the size check below
        // keeps the slice inside the bytes the call wrote.
        unsafe {
            let rec = &*ptr;
            if rec.Relationship != RelationGroup {
                return None;
            }
            let rel = &rec.Anonymous.Group;
            let n = rel.ActiveGroupCount as usize;
            let need = std::mem::offset_of!(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Anonymous)
                + std::mem::offset_of!(GROUP_RELATIONSHIP, GroupInfo)
                + n * std::mem::size_of::<PROCESSOR_GROUP_INFO>();
            if n == 0 || need > len as usize {
                return None;
            }
            let infos = std::slice::from_raw_parts(rel.GroupInfo.as_ptr(), n);
            Some(
                infos
                    .iter()
                    .enumerate()
                    .map(|(i, gi)| ProcessorGroup {
                        index: i as u16,
                        active: gi.ActiveProcessorCount as u32,
                        mask: gi.ActiveProcessorMask as u64,
                    })
                    .collect(),
            )
        }
    }

    pub fn decode_ansi(bytes: &[u8]) -> Option<String> {
        use windows_sys::Win32::Globalization::{
            CP_ACP, MB_ERR_INVALID_CHARS, MultiByteToWideChar,
        };
        if bytes.is_empty() {
            return Some(String::new());
        }
        let len = i32::try_from(bytes.len()).ok()?;
        // SAFETY: the input pointer/length describe `bytes`; a null output
        // buffer with size 0 only asks for the required length.
        let n = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                len,
                std::ptr::null_mut(),
                0,
            )
        };
        if n <= 0 {
            return None;
        }
        let mut wide = vec![0u16; n as usize];
        // SAFETY: `wide` has room for exactly `n` UTF-16 units.
        let m = unsafe {
            MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                bytes.as_ptr(),
                len,
                wide.as_mut_ptr(),
                n,
            )
        };
        if m != n {
            return None;
        }
        String::from_utf16(&wide).ok()
    }

    pub fn current_commit() -> Option<u64> {
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: an all-zero PROCESS_MEMORY_COUNTERS is valid output storage.
        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        // SAFETY: the pseudo handle of the current process is always valid;
        // `c` has `size` bytes.
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, size) };
        (ok != 0).then_some(c.PagefileUsage as u64)
    }

    pub fn ui_language() -> Option<u16> {
        // SAFETY: no arguments, no side effects.
        Some(unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() })
    }

    pub fn available_memory() -> Option<u64> {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        // SAFETY: an all-zero MEMORYSTATUSEX is valid once dwLength is set.
        let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: `m` is a valid, exclusively borrowed MEMORYSTATUSEX.
        let ok = unsafe { GlobalMemoryStatusEx(&mut m) };
        (ok != 0).then_some(m.ullAvailPhys)
    }

    pub fn process_peak_memory(
        handle: std::os::windows::io::RawHandle,
    ) -> Option<super::PeakMemory> {
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        // SAFETY: an all-zero PROCESS_MEMORY_COUNTERS is valid output storage.
        let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        // SAFETY: the caller passes a live process handle; `c` has `size` bytes.
        let ok = unsafe { K32GetProcessMemoryInfo(handle as _, &mut c, size) };
        (ok != 0).then_some(super::PeakMemory {
            working_set: c.PeakWorkingSetSize as u64,
            commit: c.PeakPagefileUsage as u64,
        })
    }

    pub fn alternate_streams(path: &std::path::Path) -> std::io::Result<Vec<(String, u64)>> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{
            ERROR_HANDLE_EOF, ERROR_INVALID_PARAMETER, GetLastError, INVALID_HANDLE_VALUE,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
            WIN32_FIND_STREAM_DATA,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let mut d = WIN32_FIND_STREAM_DATA::default();
        // SAFETY: `wide` is NUL-terminated and `d` is valid output storage
        // of the type FindStreamInfoStandard requires.
        let h = unsafe {
            FindFirstStreamW(
                wide.as_ptr(),
                FindStreamInfoStandard,
                (&raw mut d).cast(),
                0,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            // SAFETY: plain query of the calling thread's last error.
            let e = unsafe { GetLastError() };
            // No streams at all, or a file system without stream support.
            if e == ERROR_HANDLE_EOF || e == ERROR_INVALID_PARAMETER {
                return Ok(Vec::new());
            }
            return Err(std::io::Error::from_raw_os_error(e as i32));
        }
        let mut out = Vec::new();
        loop {
            let len = d
                .cStreamName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(d.cStreamName.len());
            // ":name:$DATA"; the main stream is "::$DATA".
            if let Ok(s) = String::from_utf16(&d.cStreamName[..len])
                && let Some(name) = s.strip_prefix(':').and_then(|r| r.strip_suffix(":$DATA"))
                && !name.is_empty()
            {
                out.push((name.to_string(), d.StreamSize.max(0) as u64));
            }
            // SAFETY: `h` is a live find handle and `d` valid output storage.
            if unsafe { FindNextStreamW(h, (&raw mut d).cast()) } == 0 {
                break;
            }
        }
        // SAFETY: `h` came from FindFirstStreamW and is closed once.
        unsafe { FindClose(h) };
        out.sort();
        Ok(out)
    }
    pub fn bind_current_thread(group: u16, mask: u64) -> std::io::Result<()> {
        let aff = GROUP_AFFINITY {
            Mask: mask as usize,
            Group: group,
            Reserved: [0; 3],
        };
        // SAFETY: `aff` is a valid GROUP_AFFINITY, the current-thread pseudo
        // handle needs no closing, and the previous affinity is not requested.
        let ok = unsafe { SetThreadGroupAffinity(GetCurrentThread(), &aff, std::ptr::null_mut()) };
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::ProcessorGroup;

    pub fn all_processors() -> Option<u32> {
        None
    }
    pub fn processor_groups() -> Vec<ProcessorGroup> {
        Vec::new()
    }
    pub fn bind_current_thread(_group: u16, _mask: u64) -> std::io::Result<()> {
        Ok(())
    }
    pub fn decode_ansi(_bytes: &[u8]) -> Option<String> {
        None
    }
    pub fn available_memory() -> Option<u64> {
        None
    }
    pub fn ui_language() -> Option<u16> {
        None
    }
    pub fn alternate_streams(_path: &std::path::Path) -> std::io::Result<Vec<(String, u64)>> {
        Ok(Vec::new())
    }
    pub fn current_commit() -> Option<u64> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_is_consistent() {
        let g = processor_groups();
        assert!(!g.is_empty());
        let sum: usize = g.iter().map(|g| g.active as usize).sum();
        assert_eq!(sum, logical_cpus());
        for x in &g {
            assert_eq!(x.mask.count_ones(), x.active, "{x:?}");
        }
        // available_parallelism sees at most one group: never more than the total.
        let ap = std::thread::available_parallelism().map_or(1, |n| n.get());
        assert!(ap <= logical_cpus());
    }

    #[test]
    fn binding_to_own_group_works() {
        let g = processor_groups()[0];
        std::thread::spawn(move || bind_current_thread(g.index, g.mask).unwrap())
            .join()
            .unwrap();
    }

    #[test]
    fn ansi_ascii_roundtrip() {
        if cfg!(windows) {
            assert_eq!(decode_ansi(b"plain.txt").as_deref(), Some("plain.txt"));
        } else {
            assert_eq!(decode_ansi(b"plain.txt"), None);
        }
    }

    #[test]
    fn memory_queries() {
        if cfg!(windows) {
            assert!(available_memory().unwrap() > 0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            let mut child = std::process::Command::new("cmd")
                .args(["/C", "exit"])
                .spawn()
                .unwrap();
            child.wait().unwrap();
            let p = process_peak_memory(child.as_raw_handle()).unwrap();
            assert!(p.working_set > 0 && p.commit > 0, "{p:?}");
        }
    }

    #[test]
    fn masks() {
        assert_eq!(low_mask(0), 0);
        assert_eq!(low_mask(12), 0xFFF);
        assert_eq!(low_mask(64), u64::MAX);
    }
}
