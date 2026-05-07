# BaseSec Performance & Optimization

BaseSec is designed to scan large Node.js Codebases (TypeScript/JavaScript) rapidly by leveraging caching and worker threads. This document outlines the performance characteristics of BaseSec and provides guidance on how to optimize your scans.

## Performance Highlights

By default, BaseSec v0.1.0 employs an **Analysis Cache**, which stores the result of every scanned file. This strategy achieves an order-of-magnitude speedup on incremental scans.

**Benchmark Setup**
- **Hardware:** 8-Core CPU, 16GB RAM
- **Target:** BaseSec source code (~50 files, TypeScript, AST + Taint Analysis)
- **Node version:** 18.x LTS

| Mode | Configuration | Scan Time | Memory (Peak RSS) | Improvement |
| :--- | :--- | :--- | :--- | :--- |
| **Baseline** | No Cache, No Workers | ~1600ms | ~150MB | 1.0x |
| **Workers** | No Cache, 4 Workers | ~1600ms | ~220MB | 1.0x |
| **Cached** | Cache, No Workers | ~420ms | ~90MB | ~4.0x |
| **Optimized**| Cache, 4 Workers | **~130ms** | ~110MB | **~12.0x** |

*Note: Worker thread initialization carries a fixed ~200ms overhead, meaning worker threads shine brightest on repositories with >100 files.*

## Core Optimizations

### 1. Analysis Cache (`--cache` / `--no-cache`)
The analysis cache is enabled by default. It drastically reduces scan times during active development (e.g., as a Git pre-commit hook) by only re-scanning modified files.

**How it works:**
- **File Hashing:** BaseSec computes a fast SHA-256 hash of each file's content.
- **Config Hashing:** It also hashes your BaseSec configuration (rule settings, framework settings, severity thresholds).
- **Cache Hit:** If both the file hash and config hash match a cached entry, BaseSec skips the AST parsing and taint analysis steps for that file entirely, reusing the previous findings.
- **Eviction:** Cache entries expire automatically after 24 hours. Cache files are stored in your OS's temporary directory (`os.tmpdir()`).

**When to disable caching (`--no-cache`):**
- In CI/CD environments where a clean environment is required.
- If you suspect a caching bug or staleness issue.
- When benchmarking the raw performance of rules.

### 2. Worker Threads (`--workers`)
BaseSec can distribute file parsing and taint analysis across multiple CPU cores using Node.js `worker_threads`.

**How it works:**
- **Auto-Scaling:** When running without `--workers`, BaseSec dynamically decides whether to use workers based on the number of files (disables workers for `< 50` files to avoid thread startup overhead) and sets the thread pool size to `max(1, OS_CPUS - 1)`.
- **Worker Isolation:** Each worker thread instantiates its own TypeScript Compiler API parser and Rule Engine, preventing memory leaks and avoiding V8 garbage collection pauses in the main thread.
- **Batching:** Files are streamed into a thread-safe queue. The pool spins up threads only when work is available.

**Best Practices for Workers:**
- **Small Repos (<50 files):** Pass `--workers 0` or rely on the default auto-scaling to avoid the ~200ms worker startup overhead.
- **Large Repos (>500 files):** Set `--workers <number>` manually if you want to restrict BaseSec from consuming all available CPU cores on shared infrastructure.

### 3. Fast-Glob Filtering (`--ignore`)
File path exclusion is the fastest optimization. BaseSec uses `fast-glob` for directory traversal. 
Always ensure `node_modules`, `dist`, `build`, and coverage directories are ignored. 
(BaseSec ignores these by default, but you can append more via `-i` or the `ignore` array in `.basesecrc`).

## Future Roadmap (v1.1+)
- **Lazy Rule Evaluation:** Aborting rule execution early once a single finding is detected per-rule (useful with `--strict`).
- **Memoized Framework Detection:** Caching the AST results of Express/NestJS configuration lookups across files.
- **V8 Snapshotting:** Snapshotting the Worker Thread startup state to bypass TypeScript Compiler initialization overhead.
