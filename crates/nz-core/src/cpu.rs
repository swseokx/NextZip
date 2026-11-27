//! CPU topology and the engine's Rayon thread pool.
//!
//! Windows machines with more than 64 logical CPUs have several processor
//! groups. Rust's `available_parallelism` (`GetSystemInfo`) sees only one of
//! them, which caps a process at 64 threads. NextZip counts every
//! group ([`logical_cpus`]) and spreads the pool's workers over the groups in
//! proportion to their size ([`assign_groups`]), binding each worker with
//! `SetThreadGroupAffinity` when it starts (through `nz-sys`, the crate that
//! holds the `unsafe` Win32 calls).
//!
//! Placement never changes archive bytes: every writer splits work by input
//! size (see `sevenz::PLAN_SPLIT`), not by thread count.

use anyhow::Result;

/// Logical CPUs over all processor groups.
pub fn logical_cpus() -> usize {
    nz_sys::logical_cpus().max(1)
}

/// Group index (into `sizes`) for each of `threads` workers.
///
/// Workers are shared out in proportion to the group sizes with the
/// largest-remainder method (ties go to the lower group), so a group never
/// gets more workers than CPUs while `threads <= sum(sizes)`. The order is a
/// smooth weighted round robin, so the first `k` workers are spread over the
/// groups as well. The result depends only on the arguments.
pub fn assign_groups(sizes: &[u32], threads: usize) -> Vec<usize> {
    let total: u64 = sizes.iter().map(|&s| s as u64).sum();
    if threads == 0 || sizes.is_empty() {
        return Vec::new();
    }
    if total == 0 {
        return vec![0; threads];
    }
    let t = threads as u64;
    let mut quota: Vec<u64> = sizes.iter().map(|&s| t * s as u64 / total).collect();
    let left = t - quota.iter().sum::<u64>();
    let mut by_rem: Vec<usize> = (0..sizes.len()).collect();
    // Remainder of t * s / total, larger first; stable sort keeps lower groups first on ties.
    by_rem.sort_by_key(|&g| std::cmp::Reverse(t * sizes[g] as u64 % total));
    for &g in by_rem.iter().take(left as usize) {
        quota[g] += 1;
    }
    // Smooth weighted round robin (weights = quotas).
    let mut cur = vec![0i64; sizes.len()];
    let mut out = Vec::with_capacity(threads);
    for _ in 0..threads {
        let mut best = None;
        for (g, &q) in quota.iter().enumerate() {
            if q == 0 {
                continue;
            }
            cur[g] += q as i64;
            if best.is_none_or(|b: usize| cur[g] > cur[b]) {
                best = Some(g);
            }
        }
        let b = best.expect("some group has a quota");
        cur[b] -= t as i64;
        out.push(b);
    }
    out
}

/// Rayon pool with `threads` workers. With more than one processor group,
/// worker `i` is bound to the group [`assign_groups`] gives it.
pub fn pool(threads: usize) -> Result<rayon::ThreadPool> {
    let threads = threads.max(1);
    let groups = nz_sys::processor_groups();
    let mut b = rayon::ThreadPoolBuilder::new().num_threads(threads);
    if groups.len() > 1 {
        let sizes: Vec<u32> = groups.iter().map(|g| g.active).collect();
        let plan: Vec<(u16, u64)> = assign_groups(&sizes, threads)
            .into_iter()
            .map(|g| (groups[g].index, groups[g].mask))
            .collect();
        crate::trace(&format!(
            "processor groups {sizes:?}: {threads} workers -> {:?}",
            per_group(
                &plan.iter().map(|p| p.0 as usize).collect::<Vec<_>>(),
                sizes.len()
            )
        ));
        b = b.start_handler(move |i| {
            let (g, mask) = plan[i % plan.len()];
            if let Err(e) = nz_sys::bind_current_thread(g, mask) {
                crate::trace(&format!(
                    "worker {i}: SetThreadGroupAffinity({g}) failed: {e}"
                ));
            }
        });
    }
    Ok(b.build()?)
}

/// Workers per group for an assignment.
pub fn per_group(assign: &[usize], groups: usize) -> Vec<usize> {
    let mut n = vec![0; groups];
    for &g in assign {
        n[g] += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_group_is_trivial() {
        assert_eq!(assign_groups(&[12], 12), vec![0; 12]);
        assert_eq!(assign_groups(&[12], 0), Vec::<usize>::new());
    }

    #[test]
    fn two_full_groups() {
        let a = assign_groups(&[64, 64], 128);
        assert_eq!(per_group(&a, 2), [64, 64]);
        // Interleaved: the first workers already use both groups.
        assert_eq!(&a[..4], &[0, 1, 0, 1]);
        // Fewer threads than CPUs are still split evenly.
        assert_eq!(per_group(&assign_groups(&[64, 64], 9), 2), [5, 4]);
        // More than one group's worth (the 64-thread ceiling) uses group 1.
        assert_eq!(per_group(&assign_groups(&[64, 64], 65), 2), [33, 32]);
    }

    #[test]
    fn uneven_groups() {
        // 4 groups of 48 + a short one (e.g. 212 CPUs split by the firmware).
        let sizes = [48, 48, 48, 48, 20];
        let all = assign_groups(&sizes, 212);
        assert_eq!(per_group(&all, 5), [48, 48, 48, 48, 20]);
        let a = assign_groups(&sizes, 12);
        // 12 * 48 / 212 = 2.72 (x4), 12 * 20 / 212 = 1.13: three +1 by remainder.
        assert_eq!(per_group(&a, 5), [3, 3, 3, 2, 1]);
        for t in 1..=300 {
            let a = assign_groups(&sizes, t);
            assert_eq!(a.len(), t);
            let n = per_group(&a, 5);
            for (g, &k) in n.iter().enumerate() {
                let exact = t as f64 * sizes[g] as f64 / 212.0;
                assert!(
                    (k as f64 - exact).abs() < 1.0,
                    "t={t} group {g}: {k} vs {exact}"
                );
                if t <= 212 {
                    assert!(k <= sizes[g] as usize, "t={t}: group {g} oversubscribed");
                }
            }
        }
    }

    #[test]
    fn deterministic_and_handles_odd_inputs() {
        let s = [64, 64, 64, 64];
        assert_eq!(assign_groups(&s, 100), assign_groups(&s, 100));
        assert_eq!(per_group(&assign_groups(&s, 256), 4), [64; 4]);
        assert_eq!(per_group(&assign_groups(&[0, 8], 4), 2), [0, 4]);
        assert_eq!(assign_groups(&[0, 0], 3), [0, 0, 0]);
        assert!(assign_groups(&[], 3).is_empty());
    }

    #[test]
    fn pool_uses_requested_threads() {
        let p = pool(3).unwrap();
        assert_eq!(p.current_num_threads(), 3);
        assert_eq!(p.install(rayon::current_num_threads), 3);
    }

    #[test]
    fn logical_cpus_counts_all_groups() {
        let groups: usize = nz_sys::processor_groups()
            .iter()
            .map(|g| g.active as usize)
            .sum();
        assert_eq!(logical_cpus(), groups);
    }
}
