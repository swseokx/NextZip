//! Containment for NextZip's isolated decoder process (`nz-decode.exe`).
//!
//! Legacy and rare archive formats, and RAR (C UnRAR code), are decoded in a
//! child process that never writes files: it streams member data back to
//! the parent over a pipe, and the parent sanitises names and writes the
//! output folder itself. This crate provides both halves of the boundary:
//!
//! * [`lockdown`] — called by the child as the very first thing in `main`,
//!   before it reads any untrusted byte. It
//!   1. joins a fresh job object that allows one process only (no children),
//!      caps memory and blocks UI/clipboard/desktop access; the job handle is
//!      closed afterwards, so the limits cannot be relaxed again;
//!   2. lowers its own token to **Low integrity** and removes every
//!      privilege, so it cannot write to any user file, registry key or
//!      medium-integrity process even if a decoder is exploited;
//!   3. turns on process mitigations (no dynamic code, no extension points,
//!      no remote or low-label images, strict handle checks).
//!
//!   If any step fails the child must refuse to run (fail closed).
//! * [`Contained`] — the parent puts the child into a kill-on-close job, so a
//!   child never outlives a parent that crashed or was cancelled.
//!
//! On non-Windows targets both are no-ops that report so, which keeps the
//! workspace building everywhere; NextZip ships on Windows only.

use std::io;

/// What [`lockdown`] achieved (for diagnostics and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockdown {
    pub job: bool,
    pub low_integrity: bool,
    pub privileges_removed: bool,
    pub mitigations: bool,
}

impl Lockdown {
    /// Every protection is in place.
    pub fn complete(&self) -> bool {
        self.job && self.low_integrity && self.privileges_removed && self.mitigations
    }
}

/// Lock the current process down (see the crate docs). `memory_limit` caps
/// the committed memory of this process in bytes.
pub fn lockdown(memory_limit: usize) -> io::Result<Lockdown> {
    imp::lockdown(memory_limit)
}

/// Integrity level RID of the current process token (0x1000 low, 0x2000
/// medium, 0x3000 high), or `None` where that does not apply.
pub fn integrity_level() -> Option<u32> {
    imp::integrity_level()
}

/// Detach the process's standard output for private use and point the
/// standard output handle at standard error, so stray `println!`s in
/// third-party code cannot corrupt a binary protocol spoken on the returned
/// handle.
pub fn take_stdout() -> io::Result<std::fs::File> {
    imp::take_stdout()
}

/// A child process held in a kill-on-close job object: dropping this (or the
/// parent dying) terminates the child and anything it started.
pub struct Contained {
    #[allow(dead_code)]
    job: imp::Job,
}

impl Contained {
    /// Put `child` into a new kill-on-close job.
    pub fn new(child: &std::process::Child) -> io::Result<Contained> {
        Ok(Contained {
            job: imp::Job::kill_on_close(child)?,
        })
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, CreateWellKnownSid, GetTokenInformation, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_REMOVED, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
        TokenIntegrityLevel, TokenPrivileges, WinLowLabelSid,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken, ProcessDynamicCodePolicy,
        ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy,
        SetProcessMitigationPolicy,
    };

    use super::Lockdown;

    pub fn take_stdout() -> io::Result<std::fs::File> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
        };
        // SAFETY: plain Win32 calls on this process's standard handles. The
        // original output handle is owned by the returned File from now on;
        // the standard slot is pointed elsewhere first, so std never writes
        // to (or closes) it again.
        unsafe {
            let out = GetStdHandle(STD_OUTPUT_HANDLE);
            if out.is_null() || out == INVALID_HANDLE_VALUE {
                return Err(io::Error::other("no standard output handle"));
            }
            if SetStdHandle(STD_OUTPUT_HANDLE, GetStdHandle(STD_ERROR_HANDLE)) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(std::fs::File::from_raw_handle(out))
        }
    }

    /// All JOB_OBJECT_UILIMIT_* flags (handles, read/write clipboard,
    /// system parameters, display settings, global atoms, desktop, exit
    /// windows).
    const UILIMIT_ALL: u32 = 0xFF;

    fn check(ok: i32, what: &str) -> io::Result<()> {
        if ok == 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
        }
        Ok(())
    }

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle was returned by a successful Win32 call and
            // is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn new_job(limits: u32, memory: usize, ui: bool) -> io::Result<Handle> {
        // SAFETY: plain Win32 calls with valid, fully initialised structs.
        unsafe {
            let job = CreateJobObjectW(null(), null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Handle(job);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = limits;
            info.BasicLimitInformation.ActiveProcessLimit = 1;
            info.ProcessMemoryLimit = memory;
            check(
                SetInformationJobObject(
                    job.0,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ),
                "SetInformationJobObject(limits)",
            )?;
            if ui {
                let r = JOBOBJECT_BASIC_UI_RESTRICTIONS {
                    UIRestrictionsClass: UILIMIT_ALL,
                };
                check(
                    SetInformationJobObject(
                        job.0,
                        JobObjectBasicUIRestrictions,
                        &r as *const _ as *const _,
                        size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                    ),
                    "SetInformationJobObject(ui)",
                )?;
            }
            Ok(job)
        }
    }

    fn own_job(memory: usize) -> io::Result<()> {
        let job = new_job(
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
            memory,
            true,
        )?;
        // SAFETY: valid job handle and the current-process pseudo handle.
        check(
            unsafe { AssignProcessToJobObject(job.0, GetCurrentProcess()) },
            "AssignProcessToJobObject(self)",
        )?;
        // The job is unnamed: once this handle is closed nobody (including
        // this process) can open it again to relax the limits.
        drop(job);
        Ok(())
    }

    fn token(access: u32) -> io::Result<Handle> {
        let mut t: HANDLE = std::ptr::null_mut();
        // SAFETY: out-pointer to a local.
        check(
            unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut t) },
            "OpenProcessToken",
        )?;
        Ok(Handle(t))
    }

    fn lower_integrity() -> io::Result<()> {
        let t = token(TOKEN_ADJUST_DEFAULT | TOKEN_QUERY)?;
        let mut sid = [0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut len = sid.len() as u32;
        // SAFETY: buffer and length describe `sid`.
        check(
            unsafe {
                CreateWellKnownSid(
                    WinLowLabelSid,
                    null::<core::ffi::c_void>() as _,
                    sid.as_mut_ptr() as _,
                    &mut len,
                )
            },
            "CreateWellKnownSid",
        )?;
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: sid.as_mut_ptr() as _,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        // SAFETY: `label` points into `sid`, which outlives the call.
        check(
            unsafe {
                SetTokenInformation(
                    t.0,
                    TokenIntegrityLevel,
                    &label as *const _ as *const _,
                    (size_of::<TOKEN_MANDATORY_LABEL>() + len as usize) as u32,
                )
            },
            "SetTokenInformation(integrity)",
        )
    }

    fn remove_privileges() -> io::Result<()> {
        let t = token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
        let mut need = 0u32;
        // SAFETY: size query with a null buffer.
        unsafe { GetTokenInformation(t.0, TokenPrivileges, std::ptr::null_mut(), 0, &mut need) };
        if need == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 storage keeps the TOKEN_PRIVILEGES header aligned.
        let mut buf = vec![0u64; (need as usize).div_ceil(8)];
        // SAFETY: buffer of `need` bytes.
        check(
            unsafe {
                GetTokenInformation(t.0, TokenPrivileges, buf.as_mut_ptr() as _, need, &mut need)
            },
            "GetTokenInformation(privileges)",
        )?;
        let tp = buf.as_mut_ptr() as *mut TOKEN_PRIVILEGES;
        // SAFETY: the kernel filled a TOKEN_PRIVILEGES with `PrivilegeCount`
        // trailing LUID_AND_ATTRIBUTES entries inside `buf`.
        unsafe {
            let n = (*tp).PrivilegeCount as usize;
            if n == 0 {
                return Ok(());
            }
            let first = std::ptr::addr_of_mut!((*tp).Privileges) as *mut LUID_AND_ATTRIBUTES;
            for i in 0..n {
                (*first.add(i)).Attributes = SE_PRIVILEGE_REMOVED;
            }
            check(
                AdjustTokenPrivileges(t.0, 0, tp, 0, std::ptr::null_mut(), std::ptr::null_mut()),
                "AdjustTokenPrivileges",
            )?;
        }
        Ok(())
    }

    fn mitigations() -> io::Result<()> {
        // Each policy struct is a union over a single u32 of flag bits.
        let set = |policy, flags: u32, what: &str| -> io::Result<()> {
            // SAFETY: pointer and size describe a u32 flags word.
            check(
                unsafe { SetProcessMitigationPolicy(policy, &flags as *const u32 as *const _, 4) },
                what,
            )
        };
        // ProhibitDynamicCode
        set(ProcessDynamicCodePolicy, 1, "dynamic code policy")?;
        // DisableExtensionPoints (AppInit DLLs, hooks, IMEs)
        set(
            ProcessExtensionPointDisablePolicy,
            1,
            "extension point policy",
        )?;
        // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
        set(ProcessImageLoadPolicy, 0b111, "image load policy")?;
        // RaiseExceptionOnInvalidHandleReference | permanently enabled
        set(ProcessStrictHandleCheckPolicy, 0b11, "strict handle policy")?;
        Ok(())
    }

    pub fn lockdown(memory: usize) -> io::Result<Lockdown> {
        own_job(memory)?;
        // Privileges first: the low-integrity token can still remove its own
        // privileges, but removing them first keeps the order obvious.
        remove_privileges()?;
        lower_integrity()?;
        mitigations()?;
        let low = integrity_level() == Some(0x1000);
        if !low {
            return Err(io::Error::other("integrity level did not drop to Low"));
        }
        Ok(Lockdown {
            job: true,
            low_integrity: low,
            privileges_removed: true,
            mitigations: true,
        })
    }

    pub fn integrity_level() -> Option<u32> {
        let t = token(TOKEN_QUERY).ok()?;
        let mut buf = [0u64; 16];
        let mut need = 0u32;
        // SAFETY: buffer of 128 bytes, enough for a label with one SID.
        let ok = unsafe {
            GetTokenInformation(
                t.0,
                TokenIntegrityLevel,
                buf.as_mut_ptr() as _,
                128,
                &mut need,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: the kernel wrote a TOKEN_MANDATORY_LABEL whose SID lies in
        // `buf`; the RID is the last sub-authority.
        unsafe {
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid as *const u8;
            let count = *sid.add(1) as usize;
            if count == 0 {
                return None;
            }
            let p = sid.add(8 + 4 * (count - 1)) as *const u32;
            Some(p.read_unaligned())
        }
    }

    pub struct Job(#[allow(dead_code)] Handle);

    impl Job {
        pub fn kill_on_close(child: &std::process::Child) -> io::Result<Job> {
            let job = new_job(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0, false)?;
            // SAFETY: valid job and live child process handle.
            check(
                unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE) },
                "AssignProcessToJobObject(child)",
            )?;
            Ok(Job(job))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    pub fn take_stdout() -> io::Result<std::fs::File> {
        use std::os::fd::AsFd;
        Ok(std::fs::File::from(
            io::stdout().as_fd().try_clone_to_owned()?,
        ))
    }

    use super::Lockdown;

    pub fn lockdown(_memory: usize) -> io::Result<Lockdown> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process lockdown is implemented for Windows only",
        ))
    }

    pub fn integrity_level() -> Option<u32> {
        None
    }

    pub struct Job;

    impl Job {
        pub fn kill_on_close(_child: &std::process::Child) -> io::Result<Job> {
            Ok(Job)
        }
    }
}
