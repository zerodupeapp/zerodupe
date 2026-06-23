# ZeroDupe Engine

*[Español](README.es.md)*

**A fast, careful duplicate finder and digital-hygiene tool for Linux — runs 100% locally, sends nothing to the cloud.** This is the open-source engine and command-line interface.

ZeroDupe doesn't just *find* duplicates — it helps you decide *which copy to keep* and never deletes anything irreversibly.

## What it does

- **Exact duplicates.** Progressive pipeline: group by size → physical-identity (hardlink) check → partial BLAKE3 (4 KB head+tail) → full BLAKE3 (256-bit) → **final byte-by-byte verification**. Nothing is acted on until two files are confirmed byte-identical. A re-validation guard refuses to act on any file whose size changed since the scan (TOCTTOU protection).
- **Similar images.** Perceptual hashing (pHash + dHash) with a BK-tree and geometric invariance — mirror H/V, rotations (90/180/270°) and center-crop are detected, not just re-encodes and resizes. RAW formats are supported via their embedded JPEG preview.
- **Digital hygiene.** Detects empty files/dirs, temporaries, broken symlinks, OS junk (`.DS_Store`, `Thumbs.db`), build caches and orphan sidecars, grouped by risk level. A safety blacklist never touches `.git`, live `node_modules`, etc.
- **Keeper scoring.** When a group has duplicates, ZeroDupe ranks which file to keep using content quality, EXIF metadata, filename and path signals — instead of blindly keeping the first or shortest-named file.
- **Reversible quarantine.** Files are moved to a quarantine (atomic rename + SQLite journal), never hard-deleted. Everything can be restored.

## Build

Requires a recent Rust toolchain (see `rust-toolchain.toml`).

```bash
git clone https://github.com/zerodupe/zerodupe-engine
cd zerodupe-engine
cargo build --release
# binary at target/release/zerodupe
```

## Usage

```bash
# Interactive flow (recommended): scan, review groups, choose what to quarantine
zerodupe interactive /path/to/scan

# Advanced: run the exact-duplicate pipeline and emit JSON
zerodupe scan --candidates --partial-hash --full-hash --byte-compare /path/to/scan

# Manage the quarantine
zerodupe quarantine list
zerodupe quarantine restore-all
```

Run `zerodupe --help` for the full set of subcommands (including similar-image and hygiene scans).

## Reproducible benchmark dataset

The `zerodupe_benchkit` crate generates a **deterministic** synthetic dataset with ground truth (exact duplicates, JPEG recompression/resize, geometric variants, RAW+JPEG siblings, unique files and hygiene junk) so anyone can benchmark detection precision/recall — against ZeroDupe or any other tool:

```bash
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench
```

See `crates/zerodupe_benchkit/README.md` for the ground-truth schema and metrics.

## License

MIT — see [LICENSE](LICENSE).
