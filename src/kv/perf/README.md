# iwkv performance tests

`iwkv_perf` is a self-contained performance benchmark for the iwkv key/value
storage engine. It is built and executed only in the dedicated performance
test mode and is not part of the regular test suites.

- Source: `src/kv/perf/iwkv_perf.c`
- Build rules: `src/kv/perf/Autark`
- Activation: `IWKV_RUN_PERF`

## Quick start

```sh
# Build the library and the benchmark, then run the default benchmark suite.
./build.sh -DIWKV_RUN_PERF=1

# Faster iteration: a single pass without a warm-up.
env IWKV_PERF_REPEATS=1 ./build.sh -DIWKV_RUN_PERF=1

# Select workloads and emit JSON. `IWKV_PERF_ARGS` may contain several flags;
# use the environment variable (or `-DIWKV_PERF_ARGS=--workload=scan` for a
# single flag) since `-D` values cannot contain unquoted spaces.
env IWKV_PERF_ARGS="--workload=crud,read-mostly,scan --format=json --output=perf.json" \
  ./build.sh -DIWKV_RUN_PERF=1
```

The examples use the `env VAR=value ...` form so that they work both in POSIX
shells and in `fish`.

The executable is produced in `autark-cache/src/kv/perf/iwkv_perf` and can be
invoked directly for interactive experiments:

```sh
./autark-cache/src/kv/perf/iwkv_perf --help
./autark-cache/src/kv/perf/iwkv_perf --quick --workload=scan --format=json
```

### Performance mode behaviour

Setting `IWKV_RUN_PERF`:

- builds the library in **release mode with debug info** (`BUILD_TYPE=Release`,
  `ENABLE_DEBINFO=1`) unless explicitly overridden;
- builds **only** the `iwkv_perf` tool — the regular test suites are neither
  built nor started;
- runs the benchmark after a successful build.

## Benchmark dimensions

The default matrix is `workload × concurrency × durability × dataset`.

### Workloads

| Workload      | Phases (measured in **bold**)              | Description |
|---------------|--------------------------------------------|-------------|
| `crud`        | **create**, **read**, **update**, **delete** | One pass of each CRUD operation over the full dataset. |
| `read-mostly` | load, **mixed**                             | Loads the dataset, then performs `95%` reads / `5%` updates (`4 × records` operations). |
| `scan`        | load, **scan**                              | Loads the dataset, then iterates the full keyspace with a cursor. |

The `load` phase of `read-mostly`/`scan` is reported but excluded from the
measured throughput. For `crud` all four phases (including `create`) are
measured.

### Concurrency

| Mode     | Description |
|----------|-------------|
| `single` | Everything runs on the calling thread. |
| `multi`  | Work is split across `IWKV_PERF_NUM_THREADS` threads (default `8`). |

Multi-threaded phases start from a `pthread_barrier`, so thread startup cost is
not part of the measured window. CRUD phases always use disjoint key ranges per
thread. For `read-mostly`, `--keyspace` controls whether threads share the whole
keyspace (`shared`, default) or are restricted to their own range
(`partitioned`). The `scan` workload always partitions the keyspace.

### Durability

| Mode       | Description |
|------------|-------------|
| `wal-off`  | WAL disabled. Fastest, not crash-durable. |
| `wal-on`   | WAL enabled. Durable to the WAL, fsync is deferred/batched. |
| `wal-sync` | WAL enabled plus `IWKV_SYNC` on every write (true per-operation fsync). |

### Datasets

| Name        | Records | Key | Value  | Key+value |
|-------------|---------|-----|--------|-----------|
| `small32`   | 100000  | 16B | 16B    | ~32B      |
| `small240`  | 100000  | 16B | 224B   | ~240B     |
| `small1016` | 100000  | 16B | 1000B  | ~1016B    |
| `large32`   | 1000000 | 16B | 16B    | ~32B      |

The value sizes are chosen to sit below the KVBLK power-of-two/split cliffs
described in `src/kv/data-format.txt`; see also `src/kv/iwkv.c`
(`KVBLK_IDXNUM`, `PREFIX_KEY_LEN_V2`).

`crud` and `read-mostly` use hashed (unsorted) keys; `scan` uses ordered keys so
that the keyspace can be divided into contiguous ranges.

## Build options

| Option | Default | Description |
|--------|---------|-------------|
| `IWKV_RUN_PERF` | – | Build and run the performance tests (exclusive mode). |
| `IWKV_PERF_NUM_THREADS` | `8` | Threads used by the `multi` concurrency mode. |
| `IWKV_PERF_REPEATS` | `3` | Total iterations per combination; the first is a warm-up. |
| `IWKV_PERF_READ_PCT` | `95` | Read percentage in the `read-mostly` workload. |
| `IWKV_PERF_DATASET_SMALL_NUM` | `100000` | Records in `small32`/`small240`/`small1016`. |
| `IWKV_PERF_DATASET_LARGE_NUM` | `1000000` | Records in `large32`. |
| `IWKV_PERF_ARGS` | – | Extra CLI arguments passed to the benchmark. |

The first five options can also be overridden at runtime with the environment
variables of the same name. `IWKV_PERF_DATASET_*` and `IWKV_PERF_NUM_THREADS`
are baked in as compile-time defaults; CLI flags take precedence at runtime.

## Command line reference

```
--workload=LIST   crud,read-mostly,scan      (default: crud,read-mostly)
--dataset=LIST    small32,small240,small1016,large32 (default: all)
--conc=LIST       single,multi               (default: both)
--wal=LIST        off,on,sync                (default: off,on)

--threads=N       Threads for the multi mode    (default: 8)
--repeats=N       Total iterations, first is a warm-up (default: 3)
--read-pct=N      Read percentage in read-mostly (default: 95)
--miss-pct=N      Missing-key read percentage    (default: 0)
--key-dist=MODE   uniform,zipfian                (default: uniform)
--keyspace=MODE   shared,partitioned             (default: shared)
--read-mode=MODE  alloc,copy                     (default: alloc)
--latency=on|off  Collect per-operation latency  (default: on)
--verify=MODE     off,sample,full                (default: sample)
--verify-every=N  Sampling interval for verify=sample (default: 64, rounded to a power of two)
--small=N         Records in the small datasets
--large=N         Records in the large dataset
--quick           Tiny datasets and a single iteration

--format=FMT      text,json,csv                  (default: text)
--output=FILE     Write the report into FILE
--list            List the available options and exit
-h, --help        Show help
```

List options accept comma-separated values, for example
`--workload=crud,scan --wal=off,sync`.

### Point read modes

- `alloc` (default) uses `iwkv_get()` + `iwkv_val_dispose()`, exercising the
  value allocation path.
- `copy` uses `iwkv_get_copy()` into a reusable per-thread buffer, isolating the
  engine read path from the allocator.

### Key distribution

- `uniform` — uniform random keys (default).
- `zipfian` — YCSB-style scrambled Zipfian distribution (Θ = 0.99); applies to
  `read-mostly` when the keyspace is `shared`.

### Verification

Values are self-describing (`<8-byte index><generation><filler>`). Reads and
scans can verify them to catch silent corruption:

- `sample` (default) — verify every `--verify-every`-th read/scan.
- `full` — verify every read/scan.
- `off` — no verification (fastest).

Missing-key lookups (`--miss-pct`) are expected to return `IWKV_ERROR_NOTFOUND`
and are reported separately.

## Methodology

For every combination the tool:

1. runs `IWKV_PERF_REPEATS` iterations (the first is discarded as a warm-up unless
   only one iteration is requested);
2. starts multi-threaded phases from a barrier and times only the measured window;
3. records per-operation latencies into a log2 histogram;
4. reports the **median** measured throughput across iterations with the
   **min/max** spread;
5. reports latency as **mean / p50 / p90 / p99 / p99.9 / max** (pooled across the
   measured iterations and measured phases);
6. reports database and WAL file sizes for the median iteration as a
   `peak/final` pair (`db: <peak>/<final>` and `wal: <peak>/<final>`), using
   short MB/KB forms. `peak` is the largest on-disk size observed while the
   database was open; `final` is the size after close (checkpointed/trimmed for
   the db, truncated for the WAL). For `crud` the final db size is the
   post-`delete` empty state, so the peak is the meaningful footprint.

Text output example:

```
[crud        | single | wal-off  | small32  ] records=100K     key=16B   val=16B    threads=1   measured=2
    throughput: median 913242 ops/s (min 900000, max 926000)
    create     0.120 s       833333 ops/s
    read       0.045 s      2222222 ops/s
    update     0.130 s       769230 ops/s
    delete     0.140 s       714285 ops/s
    latency: mean 1.09 us  p50 1.00 us  p90 1.50 us  p99 3.00 us  p99.9 8.00 us  max 12.00 us
    db: 32.00 MB/27.88 MB     wal: 0.00 B/0.00 B
```

A summary table with one row per combination is printed at the end.

### Machine-readable output

`--format=json` emits a provenance header, the effective configuration and one
object per combination:

```json
{
  "tool": "iwkv_perf",
  "provenance": { "git_rev": "...", "compiler": "...", "os": "...", "cpu": "...", "cores": 16, "page_size": 4096 },
  "config": { "threads": 8, "repeats": 3, ... },
  "results": [
    {
      "workload": "crud", "concurrency": "single", "durability": "wal-off",
      "dataset": "small32", "records": 100000, "key_size": 16, "value_size": 16,
      "threads": 1, "iterations": 2,
      "throughput_median": 913242, "throughput_min": 900000, "throughput_max": 926000,
      "latency_ns": { "mean": 1090, "p50": 1024, "p90": 1536, "p99": 3072, "p999": 8192, "max": 12288 },
      "phases": [ { "name": "create", "secs": 0.120, "ops": 100000 }, ... ],
      "db_peak_size": 33554432, "db_final_size": 29233152, "wal_peak_size": 0, "wal_final_size": 0
    }
  ]
}
```

`--format=csv` emits one row per combination with the columns:
`workload,concurrency,durability,dataset,records,key_size,value_size,threads,iterations,median_ops_s,min_ops_s,max_ops_s,lat_mean_ns,lat_p50_ns,lat_p99_ns,db_peak_bytes,db_final_bytes,wal_peak_bytes,wal_final_bytes`.

The provenance (git revision, compiler, CPU model, core count, page size) is
included so that runs can be compared and reproduced.

## Interpreting results and caveats

- Latency is measured **closed-loop** (from the start of each operation), so it
  does not correct for coordinated omission. Absolute tail latencies on a
  saturated system are therefore optimistic.
- Latency bucket resolution is one power of two, so reported percentiles are
  upper bounds within a factor of two.
- Enabling latency collection adds two clock reads per operation; use
  `--latency=off` for pure throughput runs.
- `wal-sync` performs an fsync per write and is typically one to two orders of
  magnitude slower than `wal-on`; this is the cost of true per-operation
  durability.
- Throughput on shared or virtualized hosts is noisy. Prefer the median of
  several iterations and compare medians rather than single runs.
- The WAL savepoint/checkpoint timers default to 10 s / 300 s. Long runs may
  cross a savepoint boundary, which adds variance; increase `--repeats` or keep
  runs short when comparing configurations.
- The benchmark unlinks its temporary database files after each combination;
  nothing is left behind in the cache directory.
