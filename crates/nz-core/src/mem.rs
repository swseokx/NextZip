//! Memory budget (1.0 KPI K9: peak memory <= 1 GB at 12 threads, adjusted to
//! the RAM that is actually free).
//!
//! The budget never changes archive bytes: it only limits how many encoders
//! run at the same time ([`Gate`]) and how many zstd workers a frame gets
//! (multithreaded zstd output does not depend on the worker count). Block and
//! segment sizes stay functions of the input and the options alone.

use std::sync::{Condvar, Mutex};

/// Upper bound of the default budget. Peak commit tracks the budget plus up
/// to ~20 MiB, so 880 MiB keeps it under 10^9 bytes (K9, strict reading):
/// measured 7z:6 / 7z:9 on the 100 MiB mixed set peak at 822 / 788 MiB.
pub const MAX_BUDGET: u64 = 880 << 20;
/// Lower bound of the default budget (below this, encoders run one at a time).
pub const MIN_BUDGET: u64 = 256 << 20;

/// Default budget: half of the free physical memory, clamped to
/// [`MIN_BUDGET`, `MAX_BUDGET`]. `NZ_MEM_MIB` overrides it (testing).
pub fn default_budget() -> u64 {
    if let Some(m) = std::env::var("NZ_MEM_MIB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return m.max(16) << 20;
    }
    budget_for(nz_sys::available_memory())
}

/// Budget for `avail` bytes of free RAM (None = unknown).
pub fn budget_for(avail: Option<u64>) -> u64 {
    match avail {
        Some(a) => (a / 2).clamp(MIN_BUDGET, MAX_BUDGET),
        None => MAX_BUDGET,
    }
}

/// Counting semaphore over bytes. A request larger than the capacity is cut
/// to the capacity, and a request is always granted when nothing else is
/// held, so it never deadlocks on its own.
pub struct Gate {
    cap: u64,
    used: Mutex<u64>,
    cv: Condvar,
}

/// Bytes held from a [`Gate`] until dropped.
pub struct Permit<'a> {
    gate: &'a Gate,
    n: u64,
}

impl Gate {
    pub fn new(cap: u64) -> Self {
        Self {
            cap: cap.max(1),
            used: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    pub fn capacity(&self) -> u64 {
        self.cap
    }

    /// Wait until `n` bytes fit, then hold them.
    pub fn acquire(&self, n: u64) -> Permit<'_> {
        let n = n.min(self.cap);
        let mut used = self.used.lock().expect("gate lock");
        while *used > 0 && *used + n > self.cap {
            used = self.cv.wait(used).expect("gate wait");
        }
        *used += n;
        Permit { gate: self, n }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut used = self.gate.used.lock().expect("gate lock");
        *used -= self.n;
        self.gate.cv.notify_all();
    }
}

/// Rough per-worker memory of a multithreaded zstd encoder at `level` with
/// 2 MiB jobs (match tables + job and overlap buffers). M1/1.0 measurement:
/// level 12 with a 64 MiB long window used ~43 MiB per worker.
pub fn zstd_worker_bytes(level: i32, overlap: u64) -> u64 {
    let tables: u64 = match level {
        ..=5 => 8 << 20,
        6..=9 => 16 << 20,
        10..=15 => 40 << 20,
        _ => 96 << 20,
    };
    tables + (6 << 20) + overlap
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn budget_follows_free_memory() {
        assert_eq!(budget_for(None), MAX_BUDGET);
        assert_eq!(budget_for(Some(64 << 30)), MAX_BUDGET);
        assert_eq!(budget_for(Some(1 << 30)), 512 << 20);
        assert_eq!(budget_for(Some(100 << 20)), MIN_BUDGET);
    }

    #[test]
    fn gate_bounds_concurrent_use() {
        let g = Gate::new(100);
        let now = AtomicU64::new(0);
        let peak = AtomicU64::new(0);
        rayon::scope(|s| {
            for _ in 0..16 {
                s.spawn(|_| {
                    let _p = g.acquire(30);
                    let n = now.fetch_add(30, Ordering::SeqCst) + 30;
                    peak.fetch_max(n, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    now.fetch_sub(30, Ordering::SeqCst);
                });
            }
        });
        assert!(peak.load(Ordering::SeqCst) <= 90);
        // Oversized requests are cut to the capacity instead of blocking forever.
        let _big = g.acquire(1000);
    }
}
