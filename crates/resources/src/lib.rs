//! The resource plan (D110).
//!
//! Every resource parameter of a scan (the memory budget, worker threads,
//! per-thread caches, split, batch and shard sizes) is derived here, once
//! at startup, from the detected [`System`] and the user's [`Overrides`],
//! and passed down. No other crate hard-codes a resource value
//! (`tests/no_resource_constants.rs` checks that).
//!
//! Limits that decide findings are not resources and stay fixed, so
//! findings never depend on the machine: the prefilter radius and context
//! lines, nesting depths, path and URL lengths, delta chain depth, the
//! allocation guards against hostile input, and the `--max-file-size`,
//! `--max-snapshot-size` and `--clone-max-size` policies. Constants of
//! that kind that look like sizes carry a `fixed:` comment saying why.
//!
//! The coefficients below are chosen so that on the reference machine
//! (8 GiB RAM, 8 CPUs) the plan reproduces the values measured best there
//! (D108, D109); smaller budgets scale every cache down, down to one
//! worker.

use std::fmt;
use std::num::NonZeroUsize;

use agentleaks_core::SplitOptions;

mod detect;
mod size;

pub use detect::System;
pub use size::{MemoryLimit, Size};

/// Default budget: this percentage of the memory available to the process
/// (the smaller of RAM and the cgroup limit).
pub const DEFAULT_PERCENT: u8 = 50;
/// The binary's fixed cost: catalogue, compiled regexes, prefilter
/// automaton (about 32 MB resident at startup with the embedded
/// catalogue). Workers share what is left of the budget.
const FIXED_COST: u64 = 32 << 20;
/// Memory a worker needs at least: its caches at their minimum plus an
/// ordinary item. Fewer workers run when the budget cannot give each this.
const WORKER_FLOOR: u64 = 32 << 20;
/// The smallest budget accepted: the fixed cost plus one worker.
pub const MIN_BUDGET: u64 = FIXED_COST + WORKER_FLOOR;
/// Memory assumed when neither RAM nor a cgroup limit can be read: the
/// smallest system the tool supports.
const ASSUMED_MEMORY: u64 = 1 << 30;

/// Lazy-DFA cache per regex and thread: share / 16, within these bounds.
/// Below the regex crate's default (2 MiB) the large catalogue sets thrash
/// and fall back to the slow NFA; above 32 MiB nothing was faster (D108).
/// It is a cap per regex (and direction), not a total: each cache grows
/// only as far as its regex needs, and raising the cap from 2 to 32 MiB
/// left the peak RSS of the 1 GiB corpus unchanged (D108).
const REGEX_CACHE: (u64, u64) = (2 << 20, 32 << 20);
/// Pack delta-base cache per blob reader: share / 64.
const READER_CACHE: (u64, u64) = (1 << 20, 8 << 20);
/// Decoded ancestors one pack walk may hold: share / 2 (the index is built
/// before blobs are read, so walks and readers never run together).
const MAX_HELD: (u64, u64) = (16 << 20, 256 << 20);
/// Pack positions classified per pass, 16 bytes each: budget / 4096.
const INDEX_CHUNK: (u64, u64) = (1 << 16, 1 << 20);
/// Split piece: share / 512. Pieces of 64 KiB to 2 MiB were equally fast
/// (D109); a text is split from four pieces on.
const SPLIT_PIECE: (u64, u64) = (64 << 10, 1 << 20);
/// Read buffer of a streamed file: share / 8192.
const IO_BUFFER: (u64, u64) = (8 << 10, 64 << 10);
/// Blob ids per `git fetch` of a blobless clone: one per 64 KiB of budget.
/// git resolves each fetched pack in memory, so smaller batches bound the
/// child process on small machines; more ids per batch save round trips.
const FETCH_BATCH: (u64, u64) = (1_000, 10_000);

/// What the user asked for; every field overrides one detected input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Overrides {
    /// `--max-memory`.
    pub max_memory: Option<MemoryLimit>,
    /// `--threads`; `None` = one worker per usable CPU.
    pub threads: Option<NonZeroUsize>,
}

/// Resource parameters of the git source. Any values are valid (zero
/// chunks and runs count as one); the index and the blobs read do not
/// depend on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTuning {
    /// Delta-base cache of each blob-reading thread (bytes).
    pub reader_cache: usize,
    /// Decoded delta ancestors one pack walk may hold (bytes); a deeper
    /// subtree is read through the object database instead.
    pub max_held: usize,
    /// Spare capacity a reused walk buffer may keep beyond its contents
    /// (bytes): max_held / 65536, so a walk holds at most about
    /// 1.4 × `max_held`.
    pub buffer_spare: usize,
    /// Pack index positions classified per pass when listing objects.
    pub index_chunk: usize,
    /// Lock stripes of the concurrent name and path interner (rounded up
    /// to a power of 2).
    pub name_shards: usize,
    /// Lock stripes of the concurrent earliest-path sets.
    pub slot_shards: usize,
    /// Consecutive blobs (pack order) a worker reads as one run, so its
    /// delta cache stays warm: one per 128 KiB of `reader_cache`.
    pub blob_run: usize,
}

/// Every resource parameter of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePlan {
    /// The detected inputs.
    pub system: System,
    /// Memory available to the process: the smaller of RAM and the cgroup
    /// limit (1 GiB if neither can be read).
    pub memory: u64,
    /// The most memory the scan may use (bytes).
    pub budget: u64,
    /// How the budget was chosen, for display.
    pub budget_from: String,
    /// Worker threads (the rayon pool).
    pub threads: usize,
    /// Lazy-DFA cache limit of each catalogue regex and regex set, per
    /// thread (bytes).
    pub regex_cache: usize,
    /// When one large text is scanned by several workers.
    pub split: SplitOptions,
    /// Read buffer of a streamed file (bytes).
    pub io_buffer: usize,
    /// Blob ids per `git fetch` when a blobless clone fetches what it scans.
    pub fetch_batch: usize,
    pub git: GitTuning,
    /// Where the plan differs from what was asked, or rests on a guess
    /// (shown as warnings).
    pub notes: Vec<String>,
}

/// An override the plan cannot honour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(String);

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlanError {}

/// `v` within `lo..=hi`, as a size.
fn clamp(v: u64, (lo, hi): (u64, u64)) -> usize {
    usize::try_from(v.clamp(lo, hi)).unwrap_or(usize::MAX)
}

/// `percent` % of `bytes`.
fn percent_of(bytes: u64, percent: u8) -> u64 {
    (u128::from(bytes) * u128::from(percent) / 100) as u64
}

impl ResourcePlan {
    /// The plan for this machine.
    pub fn detect(overrides: &Overrides) -> Result<ResourcePlan, PlanError> {
        ResourcePlan::derive(&System::detect(), overrides)
    }

    /// The default plan of the reference machine (8 GiB RAM, 8 CPUs, no
    /// cgroup limit), for tests that must not depend on the machine they
    /// run on.
    pub fn reference() -> ResourcePlan {
        let system = System {
            // fixed: the reference machine, not this one.
            ram: Some(8 << 30),
            cgroup_memory: None,
            cpus: 8,
        };
        match ResourcePlan::derive(&system, &Overrides::default()) {
            Ok(plan) => plan,
            Err(e) => unreachable!("the default plan always derives: {e}"),
        }
    }

    /// The plan for `system`; fails if `--max-memory` is below
    /// [`MIN_BUDGET`].
    pub fn derive(system: &System, overrides: &Overrides) -> Result<ResourcePlan, PlanError> {
        let mut notes = Vec::new();
        let (memory, memory_from) = match (system.ram, system.cgroup_memory) {
            (Some(r), Some(c)) if c < r => (c, "cgroup limit"),
            (Some(r), _) => (r, "RAM"),
            (None, Some(c)) => (c, "cgroup limit"),
            (None, None) => {
                notes.push(format!(
                    "the physical memory cannot be read; assuming {} (set --max-memory)",
                    Size(ASSUMED_MEMORY)
                ));
                (ASSUMED_MEMORY, "assumed")
            }
        };
        let of = format!("{} {memory_from}", Size(memory));
        let (budget, budget_from) = match overrides.max_memory {
            None => {
                let b = percent_of(memory, DEFAULT_PERCENT).max(MIN_BUDGET.min(memory));
                (b, format!("{DEFAULT_PERCENT}% of {of}"))
            }
            Some(MemoryLimit::Percent(p)) => (percent_of(memory, p), format!("{p}% of {of}")),
            Some(MemoryLimit::Bytes(b)) => {
                if b > memory {
                    notes.push(format!(
                        "--max-memory {} is more than the {of}; the system may kill the scan",
                        Size(b)
                    ));
                }
                (b, format!("--max-memory, {of}"))
            }
        };
        if overrides.max_memory.is_some() && budget < MIN_BUDGET {
            return Err(PlanError(format!(
                "--max-memory {} ({budget_from}) is below the minimum of {}",
                Size(budget),
                Size(MIN_BUDGET)
            )));
        }
        if budget < MIN_BUDGET {
            notes.push(format!(
                "only {} of memory; the scan needs about {}",
                Size(memory),
                Size(MIN_BUDGET)
            ));
        }

        let wanted = overrides
            .threads
            .map_or(system.cpus, NonZeroUsize::get)
            .max(1);
        let for_workers = budget.saturating_sub(FIXED_COST);
        let fit = usize::try_from(for_workers / WORKER_FLOOR)
            .unwrap_or(usize::MAX)
            .max(1);
        let threads = wanted.min(fit);
        if threads < wanted {
            notes.push(format!(
                "{threads} workers instead of {wanted}: each needs about {} of the {} left \
                 of the {} budget",
                Size(WORKER_FLOOR),
                Size(for_workers),
                Size(budget)
            ));
        }
        let share = for_workers / threads as u64;

        let reader_cache = clamp(share / 64, READER_CACHE);
        let max_held = clamp(share / 2, MAX_HELD);
        let piece = clamp(share / 512, SPLIT_PIECE);
        let git = GitTuning {
            reader_cache,
            max_held,
            buffer_spare: (max_held >> 16).max(64),
            index_chunk: clamp(budget / 4096, INDEX_CHUNK),
            name_shards: (threads * 8).next_power_of_two().clamp(8, 1024),
            slot_shards: (threads * 32).next_power_of_two().clamp(32, 4096),
            blob_run: (reader_cache >> 17).clamp(8, 64),
        };
        Ok(ResourcePlan {
            system: system.clone(),
            memory,
            budget,
            budget_from,
            threads,
            regex_cache: clamp(share / 16, REGEX_CACHE),
            split: SplitOptions {
                min_len: 4 * piece,
                piece,
            },
            io_buffer: clamp(share / 8192, IO_BUFFER),
            fetch_batch: clamp(budget >> 16, FETCH_BATCH),
            git,
            notes,
        })
    }

    /// One line for the stats: the budget and the workers.
    pub fn summary(&self) -> String {
        format!(
            "budget {} ({}), {} workers",
            Size(self.budget),
            self.budget_from,
            self.threads
        )
    }
}

/// The detailed plan (`--show-resources`): inputs, then every parameter.
impl fmt::Display for ResourcePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &self.system;
        let opt = |v: Option<u64>| v.map_or("none".to_owned(), |b| Size(b).to_string());
        writeln!(
            f,
            "system: RAM {}, cgroup memory limit {}, {} usable CPUs",
            opt(s.ram),
            opt(s.cgroup_memory),
            s.cpus
        )?;
        writeln!(f, "{}", self.summary())?;
        writeln!(
            f,
            "per worker: regex lazy-DFA cache {} per regex, pack delta cache {}, pack walk {} \
             (+{} spare per buffer)",
            Size(self.regex_cache as u64),
            Size(self.git.reader_cache as u64),
            Size(self.git.max_held as u64),
            Size(self.git.buffer_spare as u64),
        )?;
        writeln!(
            f,
            "texts of {} or more split into {} pieces; stream buffer {}; {} blob ids per fetch",
            Size(self.split.min_len as u64),
            Size(self.split.piece as u64),
            Size(self.io_buffer as u64),
            self.fetch_batch,
        )?;
        write!(
            f,
            "git: {} pack positions per pass, {} name and {} path-set shards, blob runs of {}",
            self.git.index_chunk, self.git.name_shards, self.git.slot_shards, self.git.blob_run
        )?;
        for n in &self.notes {
            write!(f, "\nnote: {n}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn system(ram: u64, cgroup: Option<u64>, cpus: usize) -> System {
        System {
            ram: Some(ram),
            cgroup_memory: cgroup,
            cpus,
        }
    }

    fn plan(ram: u64, cgroup: Option<u64>, cpus: usize, o: &Overrides) -> ResourcePlan {
        ResourcePlan::derive(&system(ram, cgroup, cpus), o).unwrap()
    }

    fn memory(m: &str) -> Overrides {
        Overrides {
            max_memory: Some(m.parse().unwrap()),
            ..Overrides::default()
        }
    }

    /// Upper bound of what one worker's caches hold at once (the regex
    /// caches are a cap per regex, measured in P1, and not included).
    fn per_worker_bound(p: &ResourcePlan) -> u64 {
        // A walk holds at most about 1.25 × max_held plus 10_000 spare
        // buffers (the delta chain limit) beyond what it holds.
        let walk = p.git.max_held as u64 * 5 / 4 + 10_000 * p.git.buffer_spare as u64;
        walk.max(p.git.reader_cache as u64 + p.io_buffer as u64 + 4 * p.split.piece as u64)
    }

    #[test]
    fn derivation_from_one_gib_and_one_cpu_to_64_gib_and_64_cpus() {
        for (ram, cpus) in [
            (GIB, 1),
            (GIB, 8),
            (2 * GIB, 2),
            (4 * GIB, 4),
            (8 * GIB, 8),
            (16 * GIB, 16),
            (32 * GIB, 32),
            (64 * GIB, 64),
            (64 * GIB, 1),
        ] {
            let p = plan(ram, None, cpus, &Overrides::default());
            assert_eq!(p.budget, ram / 2, "{ram} {cpus}");
            assert_eq!(p.threads, cpus, "{ram} {cpus}");
            assert!(p.notes.is_empty(), "{:?}", p.notes);
            // The fixed cost and the per-worker caches fit the budget.
            assert!(
                FIXED_COST + p.threads as u64 * per_worker_bound(&p) <= p.budget,
                "{ram} {cpus}: {p}"
            );
            assert!(p.git.name_shards.is_power_of_two());
            assert!(p.git.slot_shards.is_power_of_two());
            assert!(p.split.min_len > p.split.piece && p.split.piece > 0);
            assert!((8..=64).contains(&p.git.blob_run));
            assert!((1_000..=10_000).contains(&p.fetch_batch));
        }
    }

    #[test]
    fn the_reference_machine_keeps_the_measured_values() {
        // 8 GiB, 8 CPUs: within 2% of the values of D108/D109 and of the
        // git source before the plan existed.
        let p = ResourcePlan::reference();
        let near = |got: usize, want: u64| {
            let got = got as u64;
            assert!(got <= want && got >= want - want / 50, "{got} vs {want}");
        };
        near(p.regex_cache, 32 * MIB);
        near(p.git.reader_cache, 8 * MIB);
        near(p.git.max_held, 256 * MIB);
        near(p.git.buffer_spare, 4 << 10);
        near(p.split.piece, MIB);
        near(p.split.min_len, 4 * MIB);
        near(p.io_buffer, 64 << 10);
        near(p.git.blob_run, 64);
        assert_eq!(p.git.index_chunk, 1 << 20);
        assert_eq!((p.git.name_shards, p.git.slot_shards), (64, 256));
        assert_eq!(p.fetch_batch, 10_000);
    }

    #[test]
    fn small_budgets_shrink_caches_and_workers() {
        let one = plan(GIB, None, 8, &Overrides::default());
        assert_eq!((one.budget, one.threads), (512 * MIB, 8));
        assert_eq!(one.regex_cache as u64, 3840 << 10);
        assert_eq!(one.git.reader_cache as u64, MIB);
        assert_eq!(one.git.max_held as u64, 30 * MIB);
        assert_eq!(one.split.piece as u64, 120 << 10);
        assert_eq!(one.fetch_batch, 8192);

        // The minimum: the fixed cost and one worker.
        let tiny = plan(8 * GIB, None, 8, &memory("64M"));
        assert_eq!((tiny.budget, tiny.threads), (64 * MIB, 1));
        assert_eq!(tiny.regex_cache as u64, 2 * MIB);
        assert_eq!(tiny.git.max_held as u64, 16 * MIB);
        assert_eq!(tiny.fetch_batch, 1024);
        assert!(tiny.notes[0].starts_with("1 workers instead of 8"));
        assert!(FIXED_COST + per_worker_bound(&tiny) <= tiny.budget);

        // --threads is honoured within the budget, also above the CPUs.
        for t in [3, 16] {
            let o = Overrides {
                threads: NonZeroUsize::new(t),
                ..memory("1G")
            };
            assert_eq!(plan(8 * GIB, None, 8, &o).threads, t);
        }
    }

    #[test]
    fn memory_is_the_smaller_of_ram_and_the_cgroup_limit() {
        let p = plan(8 * GIB, Some(3 * GIB), 8, &Overrides::default());
        assert_eq!((p.memory, p.budget), (3 * GIB, 1536 * MIB));
        assert!(p.budget_from.contains("cgroup"), "{}", p.budget_from);
        let p = plan(8 * GIB, Some(16 * GIB), 8, &memory("25%"));
        assert_eq!(p.budget, 2 * GIB);
        // Unknown memory: the smallest supported system, with a note.
        let s = System {
            ram: None,
            cgroup_memory: None,
            cpus: 4,
        };
        let p = ResourcePlan::derive(&s, &Overrides::default()).unwrap();
        assert_eq!(p.budget, 512 * MIB);
        assert!(p.notes[0].contains("cannot be read"));
        // A tiny container gets all of its memory, with a note.
        let p = plan(8 * GIB, Some(48 * MIB), 8, &Overrides::default());
        assert_eq!((p.budget, p.threads), (48 * MIB, 1));
        assert!(p.notes[0].starts_with("only 48.0 MiB"), "{:?}", p.notes);
    }

    #[test]
    fn max_memory_below_the_minimum_is_refused() {
        let s = system(8 * GIB, None, 8);
        let err = ResourcePlan::derive(&s, &memory("63M")).unwrap_err();
        assert!(err.to_string().contains("below the minimum"), "{err}");
        // A percentage names what it was taken of.
        let small = system(100 * MIB, None, 8);
        let err = ResourcePlan::derive(&small, &memory("50%")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "--max-memory 50.0 MiB (50% of 100.0 MiB RAM) is below the minimum of 64.0 MiB"
        );
        // ... while the default there is raised to the minimum.
        let p = ResourcePlan::derive(&small, &Overrides::default()).unwrap();
        assert_eq!(p.budget, MIN_BUDGET);
        // Above the available memory: honoured, with a warning.
        let p = ResourcePlan::derive(&s, &memory("16G")).unwrap();
        assert_eq!(p.budget, 16 * GIB);
        assert!(p.notes[0].contains("may kill"), "{:?}", p.notes);
    }

    #[test]
    fn extreme_systems_derive_without_panicking() {
        for ram in [0, 1, MIB, GIB, u64::MAX] {
            for cgroup in [None, Some(0), Some(MIB), Some(u64::MAX)] {
                for cpus in [1, 7, 1024] {
                    for o in [Overrides::default(), memory("100%"), memory("16T")] {
                        let p = ResourcePlan::derive(&system(ram, cgroup, cpus), &o);
                        if let Ok(p) = p {
                            assert!(p.threads >= 1 && p.threads <= cpus.max(1));
                            assert!(p.split.piece > 0 && p.fetch_batch > 0);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn display_names_every_parameter() {
        let p = plan(8 * GIB, None, 8, &memory("2G"));
        let s = p.to_string();
        for part in [
            "RAM 8.0 GiB",
            "budget 2.0 GiB (--max-memory",
            "8 workers",
            "regex lazy-DFA cache",
            "pack delta cache",
            "split into",
            "blob ids per fetch",
            "blob runs of",
        ] {
            assert!(s.contains(part), "{part}: {s}");
        }
    }
}
