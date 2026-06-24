# ZeroDupe Engine

*[Español](README.es.md)*

![License](https://img.shields.io/badge/license-MIT-blue)
![Rust](https://img.shields.io/badge/rust-2024_edition-orange)
![Platform](https://img.shields.io/badge/platform-Linux-333)
![Privacy](https://img.shields.io/badge/cloud-none-success)

**A fast, careful duplicate finder and digital-hygiene tool — 100% local, sends nothing to the cloud.** This is the open-source engine and CLI behind ZeroDupe.

It doesn't just *find* duplicates — it helps you decide **which copy to keep**, and never deletes anything irreversibly.

## Features

- 🎯 **Exact duplicates** — Progressive pipeline that does the least work possible: group by size → hardlink (physical-identity) check → partial BLAKE3 (4 KB head+tail) → full BLAKE3 (256-bit) → **final byte-by-byte verification**. Nothing is acted on until two files are confirmed byte-identical.
- 🖼️ **Similar images** — Perceptual hashing (pHash + dHash) over a BK-tree with geometric invariance: mirror H/V, rotations (90/180/270°) and center-crop, not just re-encodes/resizes. Common RAW formats (CR2, NEF, ARW, DNG and more) via embedded JPEG preview (`rawler`). Each group ships a confidence label.
- 🧹 **Digital hygiene** — Seven detectors for empty files/dirs, temporaries, broken symlinks, OS junk (`.DS_Store`, `Thumbs.db`), build caches and orphan sidecars, classified into three risk tiers. A safety blacklist never touches `.git`, live `node_modules`, etc.
- 🏆 **Keeper scoring** — Picks which file to keep from content quality, EXIF metadata, filename and path signals — not "first found" or "shortest name".
- ♻️ **Reversible quarantine** — Files move to an SQLite-journaled quarantine via atomic rename, never hard-deleted. Restore anything; 30-day auto-purge.
- ⚡ **Smart cache** — SQLite hash cache keyed on device/inode/size/mtime turns re-scans from minutes into milliseconds. Nanosecond-precision witnesses (device/inode/size/mtime) guard against stale cache entries.
- 🌐 **Bilingual CLI** — English and Spanish output, auto-detected from `LANG`.

## Architecture

A Rust workspace of 16 crates (`edition = "2024"`, MSRV 1.95):

| Layer        | Crates                                          | Role                                            |
|--------------|-------------------------------------------------|-------------------------------------------------|
| Core         | `core` · `fs` · `hash` · `platform` · `config`  | Types, discovery, hashing, OS glue, config      |
| Exact        | `scan` · `cache`                                | Exact-duplicate pipeline + hash cache           |
| Similar      | `similar` · `similar_image` · `policy`          | Perceptual hashing + keeper scoring             |
| Hygiene      | `hygiene`                                       | Seven junk detectors, three risk tiers          |
| Operation    | `workflow` · `safety` · `report`                | State machine, quarantine, HTML reports         |
| Interface    | `cli` · `benchkit`                              | Command line + reproducible benchmark dataset   |

## Build

Requires a recent Rust toolchain (see `rust-toolchain.toml`).

```bash
git clone https://github.com/zerodupeapp/zerodupe
cd zerodupe
cargo build --release
# binary at target/release/zerodupe
```

## Usage

```bash
# Interactive flow (recommended): scan, review groups, choose what to quarantine
zerodupe interactive /path/to/scan

# Single-purpose scans
zerodupe similar  /path/to/scan     # near-duplicate images only
zerodupe hygiene  /path/to/scan     # junk only (add --dry-run to report without moving)

# Advanced: run the exact pipeline and emit JSON for scripting
zerodupe scan --candidates --partial-hash --full-hash --byte-compare --json /path/to/scan

# Manage the quarantine
zerodupe quarantine list
zerodupe quarantine restore-all
```

Run `zerodupe --help` for the full set of subcommands and flags.

## Reproducible benchmark dataset

The `zerodupe_benchkit` crate generates a **deterministic** synthetic dataset with ground truth (exact duplicates, JPEG recompression/resize, geometric variants, RAW+JPEG siblings, unique files and hygiene junk) so anyone can measure detection precision/recall — against ZeroDupe or any other tool:

```bash
cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench
```

See `crates/zerodupe_benchkit/README.md` for the ground-truth schema and metrics.

## Privacy

No cloud, no telemetry, no network calls. Everything runs on your machine.

## License

MIT — see [LICENSE](LICENSE).
