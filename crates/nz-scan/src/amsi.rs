//! Thin AMSI wrapper (the only `unsafe` in this crate). Used inside the
//! scanner process only: AMSI providers (Defender's `MpOav.dll` and third
//! party engines) load into the calling process, so a provider crash or
//! slow start never touches the front end.

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::System::Antimalware::{
        AMSI_RESULT, AmsiCloseSession, AmsiInitialize, AmsiOpenSession, AmsiScanBuffer,
        AmsiUninitialize, HAMSICONTEXT, HAMSISESSION,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// An initialised AMSI context.
    pub struct Amsi {
        ctx: HAMSICONTEXT,
    }

    // SAFETY: an AMSI context may be used from any thread (documented as
    // thread safe); we only move it, never share it without `&self`.
    unsafe impl Send for Amsi {}

    impl Amsi {
        /// `AmsiInitialize`; the HRESULT on failure.
        pub fn new(app: &str) -> Result<Amsi, i32> {
            let name = wide(app);
            let mut ctx: HAMSICONTEXT = std::ptr::null_mut();
            // SAFETY: `name` is NUL terminated and outlives the call; `ctx`
            // is a valid out pointer.
            let hr = unsafe { AmsiInitialize(name.as_ptr(), &mut ctx) };
            if hr < 0 || ctx.is_null() {
                return Err(hr);
            }
            Ok(Amsi { ctx })
        }

        /// Start a session: AMSI correlates the buffers scanned in it as
        /// parts of one item.
        pub fn session(&self) -> Session<'_> {
            let mut s: HAMSISESSION = std::ptr::null_mut();
            // SAFETY: valid context and out pointer. On failure `s` stays
            // null, which AmsiScanBuffer accepts as "no session".
            let hr = unsafe { AmsiOpenSession(self.ctx, &mut s) };
            if hr < 0 {
                s = std::ptr::null_mut();
            }
            Session { amsi: self, s }
        }
    }

    impl Drop for Amsi {
        fn drop(&mut self) {
            // SAFETY: context from AmsiInitialize, released once.
            unsafe { AmsiUninitialize(self.ctx) }
        }
    }

    pub struct Session<'a> {
        amsi: &'a Amsi,
        s: HAMSISESSION,
    }

    impl Session<'_> {
        /// `AmsiScanBuffer`: the raw `AMSI_RESULT`, or the HRESULT.
        pub fn scan(&self, name: &str, data: &[u8]) -> Result<i32, i32> {
            let name = wide(name);
            let len = u32::try_from(data.len()).map_err(|_| -1)?;
            let mut r: AMSI_RESULT = 0;
            // SAFETY: `data` is valid for `len` bytes, `name` is NUL
            // terminated, both outlive the call; `r` is a valid out pointer.
            let hr = unsafe {
                AmsiScanBuffer(
                    self.amsi.ctx,
                    data.as_ptr().cast(),
                    len,
                    name.as_ptr(),
                    self.s,
                    &mut r,
                )
            };
            if hr < 0 { Err(hr) } else { Ok(r) }
        }
    }

    impl Drop for Session<'_> {
        fn drop(&mut self) {
            if !self.s.is_null() {
                // SAFETY: session opened on this context, closed once.
                unsafe { AmsiCloseSession(self.amsi.ctx, self.s) }
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    /// AMSI exists on Windows only.
    pub struct Amsi;

    impl Amsi {
        pub fn new(_app: &str) -> Result<Amsi, i32> {
            Err(-1)
        }
        pub fn session(&self) -> Session<'_> {
            Session(std::marker::PhantomData)
        }
    }

    pub struct Session<'a>(std::marker::PhantomData<&'a ()>);

    impl Session<'_> {
        pub fn scan(&self, _name: &str, _data: &[u8]) -> Result<i32, i32> {
            Err(-1)
        }
    }
}

pub use imp::{Amsi, Session};
