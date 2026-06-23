//! `gen-dataset` — synthetic duplicate-detection dataset generator with ground
//! truth, for the comparative benchmark of ZeroDupe vs fdupes / jdupes / rmlint
//! / czkawka.
//!
//! Everything is **deterministic** (seeded): the same `--seed` and `--scale`
//! reproduce the same dataset byte-for-byte, so the benchmark is replicable by
//! anyone. It writes a directory tree plus a `ground_truth.json` describing
//! exactly what was planted, so a scorer can compute precision/recall/F1
//! against any tool's output.
//!
//! Planted categories (each tagged in the ground truth):
//!   * exact duplicates (byte-identical copies in different folders/names)
//!   * near-identical images: JPEG recompression, resize, format change
//!   * geometric variants — mirror H/V, rotate 90/180/270, center-crop 80%
//!     (the key test: most perceptual hashes are NOT rotation/mirror invariant)
//!   * RAW+JPEG sibling pairs that must NOT be grouped together
//!   * unique files (to measure false positives)
//!   * hygiene junk (empty files/dirs, temporaries, broken symlink, OS junk,
//!     build caches)
//!
//! Usage:
//!   cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench
//!   cargo run -p zerodupe_benchkit --bin gen-dataset -- --out /tmp/zd_bench --scale 4 --seed 7

use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use image::{Rgb, RgbImage};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "gen-dataset",
    about = "Generate a synthetic duplicate-detection dataset with ground truth"
)]
struct Args {
    /// Output directory (created; must be empty or non-existent).
    #[arg(long)]
    out: PathBuf,

    /// Seed for deterministic generation.
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Count multiplier — scale the dataset up for I/O / scale testing.
    #[arg(long, default_value_t = 1)]
    scale: usize,

    /// Optional directory of real RAW files (.cr2/.nef/.arw/.dng...). When
    /// given, each is paired with a generated JPEG sibling to exercise the
    /// real RAW path; otherwise a placeholder sibling is written and flagged.
    #[arg(long)]
    raw_samples: Option<PathBuf>,

    /// Overwrite the output directory if it already exists.
    #[arg(long, default_value_t = false)]
    force: bool,
}

/// Small deterministic PRNG (SplitMix64) — avoids any nondeterminism so the
/// dataset is byte-reproducible from the seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in `0..n` (n > 0).
    fn range(&mut self, n: u32) -> u32 {
        (self.next_u64() % n as u64) as u32
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
    fn color(&mut self) -> Rgb<u8> {
        Rgb([self.byte(), self.byte(), self.byte()])
    }
}

// ── Ground-truth schema (serialized to ground_truth.json) ──

#[derive(Serialize)]
struct GroundTruth {
    version: u32,
    seed: u64,
    scale: usize,
    /// Human notes / caveats (e.g. placeholder RAW siblings).
    notes: Vec<String>,
    /// Sets of byte-identical files. A tool is correct iff it groups exactly
    /// these together.
    exact_duplicate_groups: Vec<ExactGroup>,
    /// Perceptual clusters: base + transformed variants that SHOULD be grouped.
    similar_clusters: Vec<SimilarCluster>,
    /// Pairs that must NOT be merged (RAW+JPEG siblings of the same shot).
    should_not_group: Vec<SiblingPair>,
    /// Standalone files with no duplicate — grouping any of these is a false
    /// positive.
    unique_files: Vec<String>,
    /// Hygiene junk by category.
    hygiene: Hygiene,
    counts: Counts,
}

#[derive(Serialize)]
struct ExactGroup {
    id: String,
    kind: String, // "image" | "binary" | "text"
    files: Vec<String>,
}

#[derive(Serialize)]
struct SimilarCluster {
    id: String,
    /// "recompress" (JPEG quality / resize / format change) or "geometric"
    /// (mirror / rotation / crop).
    kind: String,
    base: String,
    variants: Vec<Variant>,
}

#[derive(Serialize)]
struct Variant {
    path: String,
    /// e.g. "jpeg_q35", "resize_50", "png", "flip_h", "rot_90", "crop_80".
    transform: String,
}

#[derive(Serialize)]
struct SiblingPair {
    files: Vec<String>,
    reason: String,
    /// true when the RAW side is a real camera file (from --raw-samples).
    real_raw: bool,
}

#[derive(Serialize, Default)]
struct Hygiene {
    empty_files: Vec<String>,
    empty_dirs: Vec<String>,
    temporary_files: Vec<String>,
    broken_symlinks: Vec<String>,
    system_junk: Vec<String>,
    cache_dirs: Vec<String>,
}

#[derive(Serialize, Default)]
struct Counts {
    exact_groups: usize,
    exact_redundant_copies: usize,
    similar_clusters_recompress: usize,
    similar_clusters_geometric: usize,
    geometric_variants: usize,
    sibling_pairs: usize,
    unique_files: usize,
    hygiene_items: usize,
    total_files: usize,
}

type Err = Box<dyn std::error::Error>;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Err> {
    let args = Args::parse();
    let root = &args.out;

    if root.exists() && args.force {
        fs::remove_dir_all(root)?;
    } else if root.exists() && fs::read_dir(root)?.next().is_some() {
        return Err(format!(
            "output dir {} is not empty (use --force to overwrite)",
            root.display()
        )
        .into());
    }
    fs::create_dir_all(root)?;

    let mut rng = Rng::new(args.seed);
    let scale = args.scale.max(1);
    let mut gt = GroundTruth {
        version: 1,
        seed: args.seed,
        scale,
        notes: Vec::new(),
        exact_duplicate_groups: Vec::new(),
        similar_clusters: Vec::new(),
        should_not_group: Vec::new(),
        unique_files: Vec::new(),
        hygiene: Hygiene::default(),
        counts: Counts::default(),
    };

    gen_exact_duplicates(root, &mut rng, scale, &mut gt)?;
    gen_recompress_clusters(root, &mut rng, scale, &mut gt)?;
    gen_geometric_clusters(root, &mut rng, scale, &mut gt)?;
    gen_siblings(root, &mut rng, scale, args.raw_samples.as_deref(), &mut gt)?;
    gen_unique(root, &mut rng, scale, &mut gt)?;
    gen_hygiene(root, &mut rng, scale, &mut gt)?;

    finalize_counts(&mut gt);

    let json = serde_json::to_string_pretty(&gt)?;
    fs::write(root.join("ground_truth.json"), json)?;

    println!("Dataset written to {}", root.display());
    println!(
        "  exact groups:        {} ({} redundant copies)",
        gt.counts.exact_groups, gt.counts.exact_redundant_copies
    );
    println!(
        "  similar (recompress): {} clusters",
        gt.counts.similar_clusters_recompress
    );
    println!(
        "  similar (geometric):  {} clusters / {} variants  <-- key test",
        gt.counts.similar_clusters_geometric, gt.counts.geometric_variants
    );
    println!("  sibling pairs:       {}", gt.counts.sibling_pairs);
    println!("  unique files:        {}", gt.counts.unique_files);
    println!("  hygiene items:       {}", gt.counts.hygiene_items);
    println!("  total files:         {}", gt.counts.total_files);
    println!("Ground truth: {}", root.join("ground_truth.json").display());
    Ok(())
}

// ── Image synthesis ──

/// Builds a structured (non-degenerate) image so perceptual hashes have real
/// DCT/gradient energy: a diagonal gradient overlaid with filled rectangles
/// and discs at seed-derived positions.
fn make_base_image(rng: &mut Rng, w: u32, h: u32) -> RgbImage {
    let mut img = RgbImage::new(w, h);
    let c0 = rng.color();
    let c1 = rng.color();
    for y in 0..h {
        for x in 0..w {
            let t = (x as f32 / w as f32 + y as f32 / h as f32) * 0.5;
            img.put_pixel(x, y, lerp_color(c0, c1, t));
        }
    }
    let shapes = 5 + rng.range(6);
    for _ in 0..shapes {
        let rw = 16 + rng.range(w / 2);
        let rh = 16 + rng.range(h / 2);
        let x = rng.range(w);
        let y = rng.range(h);
        fill_rect(&mut img, x, y, rw, rh, rng.color());
    }
    let discs = 2 + rng.range(4);
    for _ in 0..discs {
        let cx = rng.range(w);
        let cy = rng.range(h);
        let r = 10 + rng.range(w / 6);
        fill_disc(&mut img, cx, cy, r, rng.color());
    }
    img
}

fn lerp_color(a: Rgb<u8>, b: Rgb<u8>, t: f32) -> Rgb<u8> {
    let t = t.clamp(0.0, 1.0);
    let l = |i: usize| (a[i] as f32 * (1.0 - t) + b[i] as f32 * t) as u8;
    Rgb([l(0), l(1), l(2)])
}

fn fill_rect(img: &mut RgbImage, x: u32, y: u32, w: u32, h: u32, c: Rgb<u8>) {
    let (iw, ih) = img.dimensions();
    for yy in y..(y + h).min(ih) {
        for xx in x..(x + w).min(iw) {
            img.put_pixel(xx, yy, c);
        }
    }
}

fn fill_disc(img: &mut RgbImage, cx: u32, cy: u32, r: u32, c: Rgb<u8>) {
    let (iw, ih) = img.dimensions();
    let r2 = (r * r) as i64;
    let x0 = cx.saturating_sub(r);
    let y0 = cy.saturating_sub(r);
    for yy in y0..(cy + r).min(ih) {
        for xx in x0..(cx + r).min(iw) {
            let dx = xx as i64 - cx as i64;
            let dy = yy as i64 - cy as i64;
            if dx * dx + dy * dy <= r2 {
                img.put_pixel(xx, yy, c);
            }
        }
    }
}

fn save_jpeg(img: &RgbImage, path: &Path, quality: u8) -> Result<(), Err> {
    use image::codecs::jpeg::JpegEncoder;
    let file = fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    let mut encoder = JpegEncoder::new_with_quality(&mut writer, quality);
    encoder.encode_image(img)?;
    writer.flush()?;
    Ok(())
}

// ── Generators ──

fn gen_exact_duplicates(
    root: &Path,
    rng: &mut Rng,
    scale: usize,
    gt: &mut GroundTruth,
) -> Result<(), Err> {
    let dir = root.join("exact");
    // Spread copies across several folders to defeat name/path heuristics.
    let folders = ["downloads", "backup", "Photos/2021", "usb_recovered", "tmp"];
    for f in folders {
        fs::create_dir_all(dir.join(f))?;
    }

    let n = 6 * scale;
    for i in 0..n {
        // Rotate file kind so we cover image, binary blob and text.
        let (bytes, ext, kind) = match i % 3 {
            0 => {
                let img = make_base_image(rng, 256, 256);
                let tmp = dir.join(format!(".stage_{i}.jpg"));
                save_jpeg(&img, &tmp, 88)?;
                let b = fs::read(&tmp)?;
                fs::remove_file(&tmp)?;
                (b, "jpg", "image")
            }
            1 => {
                // Seeded binary blob; one larger every few to stress I/O.
                let size = if i % 6 == 1 { 4_000_000 } else { 200_000 };
                let mut b = vec![0u8; size];
                for byte in b.iter_mut() {
                    *byte = rng.byte();
                }
                (b, "bin", "binary")
            }
            _ => {
                let mut s = String::new();
                for _ in 0..(50 + rng.range(200)) {
                    s.push_str(&format!("line {} value {}\n", rng.range(10000), rng.range(10000)));
                }
                (s.into_bytes(), "txt", "text")
            }
        };

        let copies = 3; // 1 keeper + 2 redundant
        let mut files = Vec::new();
        for c in 0..copies {
            let folder = folders[(i + c) % folders.len()];
            // Different names per copy so detection can't rely on filename.
            let name = format!("file_{i}_copy{c}.{ext}");
            let rel = format!("exact/{folder}/{name}");
            let full = root.join(&rel);
            fs::write(&full, &bytes)?;
            files.push(rel);
        }
        gt.exact_duplicate_groups.push(ExactGroup {
            id: format!("exact_{i}"),
            kind: kind.to_string(),
            files,
        });
    }
    Ok(())
}

fn gen_recompress_clusters(
    root: &Path,
    rng: &mut Rng,
    scale: usize,
    gt: &mut GroundTruth,
) -> Result<(), Err> {
    let dir = root.join("similar_recompress");
    fs::create_dir_all(&dir)?;
    let n = 8 * scale;
    for i in 0..n {
        let base = make_base_image(rng, 320, 320);
        let base_rel = format!("similar_recompress/img_{i}_orig.jpg");
        save_jpeg(&base, &root.join(&base_rel), 92)?;

        let mut variants = Vec::new();

        // Heavy JPEG recompression.
        let q35_rel = format!("similar_recompress/img_{i}_q35.jpg");
        save_jpeg(&base, &root.join(&q35_rel), 35)?;
        variants.push(Variant { path: q35_rel, transform: "jpeg_q35".into() });

        // Mild recompression.
        let q75_rel = format!("similar_recompress/img_{i}_q75.jpg");
        save_jpeg(&base, &root.join(&q75_rel), 75)?;
        variants.push(Variant { path: q75_rel, transform: "jpeg_q75".into() });

        // Downscale to 50%.
        let small = image::imageops::resize(&base, 160, 160, image::imageops::FilterType::Lanczos3);
        let resize_rel = format!("similar_recompress/img_{i}_half.jpg");
        save_jpeg(&small, &root.join(&resize_rel), 88)?;
        variants.push(Variant { path: resize_rel, transform: "resize_50".into() });

        // Format change to PNG (lossless, same pixels).
        let png_rel = format!("similar_recompress/img_{i}.png");
        base.save(root.join(&png_rel))?;
        variants.push(Variant { path: png_rel, transform: "png".into() });

        gt.similar_clusters.push(SimilarCluster {
            id: format!("recompress_{i}"),
            kind: "recompress".into(),
            base: base_rel,
            variants,
        });
    }
    Ok(())
}

fn gen_geometric_clusters(
    root: &Path,
    rng: &mut Rng,
    scale: usize,
    gt: &mut GroundTruth,
) -> Result<(), Err> {
    let dir = root.join("similar_geometric");
    fs::create_dir_all(&dir)?;
    let n = 10 * scale;
    for i in 0..n {
        let base = make_base_image(rng, 320, 320);
        let base_rel = format!("similar_geometric/img_{i}_orig.jpg");
        save_jpeg(&base, &root.join(&base_rel), 90)?;

        let mut variants = Vec::new();

        let push = |variants: &mut Vec<Variant>,
                    root: &Path,
                    img: &RgbImage,
                    i: usize,
                    name: &str,
                    transform: &str|
         -> Result<(), Err> {
            let rel = format!("similar_geometric/img_{i}_{name}.jpg");
            save_jpeg(img, &root.join(&rel), 90)?;
            variants.push(Variant { path: rel, transform: transform.into() });
            Ok(())
        };

        push(&mut variants, root, &image::imageops::flip_horizontal(&base), i, "flip_h", "flip_h")?;
        push(&mut variants, root, &image::imageops::flip_vertical(&base), i, "flip_v", "flip_v")?;
        push(&mut variants, root, &image::imageops::rotate90(&base), i, "rot90", "rot_90")?;
        push(&mut variants, root, &image::imageops::rotate180(&base), i, "rot180", "rot_180")?;
        push(&mut variants, root, &image::imageops::rotate270(&base), i, "rot270", "rot_270")?;

        // Center crop to 80%.
        let (w, h) = base.dimensions();
        let cw = w * 8 / 10;
        let ch = h * 8 / 10;
        let cropped = image::imageops::crop_imm(&base, w / 10, h / 10, cw, ch).to_image();
        push(&mut variants, root, &cropped, i, "crop80", "crop_80")?;

        gt.similar_clusters.push(SimilarCluster {
            id: format!("geometric_{i}"),
            kind: "geometric".into(),
            base: base_rel,
            variants,
        });
    }
    Ok(())
}

fn gen_siblings(
    root: &Path,
    rng: &mut Rng,
    scale: usize,
    raw_samples: Option<&Path>,
    gt: &mut GroundTruth,
) -> Result<(), Err> {
    let dir = root.join("siblings");
    fs::create_dir_all(&dir)?;

    // Real RAW files, if provided.
    let mut real_raws: Vec<PathBuf> = Vec::new();
    if let Some(rs) = raw_samples
        && let Ok(entries) = fs::read_dir(rs)
    {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                real_raws.push(p);
            }
        }
    }

    let n = 4 * scale;
    for i in 0..n {
        let img = make_base_image(rng, 320, 320);
        let jpg_rel = format!("siblings/IMG_{i:04}.jpg");
        save_jpeg(&img, &root.join(&jpg_rel), 90)?;

        let (raw_rel, real_raw) = if let Some(src) = real_raws.get(i % real_raws.len().max(1)) {
            // Copy a real RAW, renamed to share the JPEG basename.
            let ext = src
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("dng")
                .to_lowercase();
            let rel = format!("siblings/IMG_{i:04}.{ext}");
            fs::copy(src, root.join(&rel))?;
            (rel, true)
        } else {
            // Placeholder sibling — flagged so the scorer knows the real RAW
            // decode path was NOT exercised here.
            let rel = format!("siblings/IMG_{i:04}.dng");
            fs::write(root.join(&rel), b"PLACEHOLDER-RAW (provide --raw-samples for the real RAW test)")?;
            (rel, false)
        };

        gt.should_not_group.push(SiblingPair {
            files: vec![jpg_rel, raw_rel],
            reason: "raw_jpeg_sibling".into(),
            real_raw,
        });
    }

    if real_raws.is_empty() {
        gt.notes.push(
            "RAW siblings use placeholder .dng files; pass --raw-samples <dir> with real RAW files (e.g. from raw.pixls.us) to exercise the real RAW decode path.".into(),
        );
    }
    Ok(())
}

fn gen_unique(root: &Path, rng: &mut Rng, scale: usize, gt: &mut GroundTruth) -> Result<(), Err> {
    let dir = root.join("unique");
    fs::create_dir_all(&dir)?;
    let n = 20 * scale;
    for i in 0..n {
        // Distinct structured images — no duplicates, no near-variants.
        let w = 256 + rng.range(128);
        let h = 256 + rng.range(128);
        let img = make_base_image(rng, w, h);
        let rel = format!("unique/uniq_{i}.jpg");
        save_jpeg(&img, &root.join(&rel), 90)?;
        gt.unique_files.push(rel);
    }
    Ok(())
}

fn gen_hygiene(root: &Path, rng: &mut Rng, scale: usize, gt: &mut GroundTruth) -> Result<(), Err> {
    let dir = root.join("hygiene");
    fs::create_dir_all(&dir)?;
    let n = 3 * scale;

    // Empty files.
    for i in 0..n {
        let rel = format!("hygiene/empty_{i}.dat");
        fs::write(root.join(&rel), b"")?;
        gt.hygiene.empty_files.push(rel);
    }
    // Empty dirs.
    for i in 0..n {
        let rel = format!("hygiene/empty_dir_{i}");
        fs::create_dir_all(root.join(&rel))?;
        gt.hygiene.empty_dirs.push(rel);
    }
    // Temporary files.
    for (i, ext) in ["tmp", "bak", "swp", "crdownload"].iter().enumerate() {
        let rel = format!("hygiene/leftover_{i}.{ext}");
        let mut content = Vec::new();
        for _ in 0..64 {
            content.push(rng.byte());
        }
        fs::write(root.join(&rel), content)?;
        gt.hygiene.temporary_files.push(rel);
    }
    // System junk.
    for name in [".DS_Store", "Thumbs.db", "desktop.ini"] {
        let rel = format!("hygiene/{name}");
        fs::write(root.join(&rel), b"junk")?;
        gt.hygiene.system_junk.push(rel);
    }
    // Build cache dir.
    let cache_rel = "hygiene/__pycache__".to_string();
    fs::create_dir_all(root.join(&cache_rel))?;
    fs::write(root.join(&cache_rel).join("module.cpython-311.pyc"), b"\x00\x00cache")?;
    gt.hygiene.cache_dirs.push(cache_rel);

    // Broken symlink (Unix only).
    #[cfg(unix)]
    {
        let rel = "hygiene/broken_link".to_string();
        let link = root.join(&rel);
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("does_not_exist_target_xyz", &link)?;
        gt.hygiene.broken_symlinks.push(rel);
    }
    #[cfg(not(unix))]
    {
        gt.notes
            .push("broken symlink not generated (non-Unix platform)".into());
    }

    Ok(())
}

fn finalize_counts(gt: &mut GroundTruth) {
    let mut exact_redundant_copies = 0usize;
    let mut total = 0usize;
    for g in &gt.exact_duplicate_groups {
        total += g.files.len();
        exact_redundant_copies += g.files.len().saturating_sub(1);
    }

    let mut similar_clusters_geometric = 0usize;
    let mut similar_clusters_recompress = 0usize;
    let mut geometric_variants = 0usize;
    for cl in &gt.similar_clusters {
        total += 1 + cl.variants.len(); // base + variants
        if cl.kind == "geometric" {
            similar_clusters_geometric += 1;
            geometric_variants += cl.variants.len();
        } else {
            similar_clusters_recompress += 1;
        }
    }

    for s in &gt.should_not_group {
        total += s.files.len();
    }
    total += gt.unique_files.len();

    let h = &gt.hygiene;
    let hygiene_items = h.empty_files.len()
        + h.empty_dirs.len()
        + h.temporary_files.len()
        + h.broken_symlinks.len()
        + h.system_junk.len()
        + h.cache_dirs.len();
    // Only count junk that materializes as real files in the tree total.
    total += h.empty_files.len() + h.temporary_files.len() + h.system_junk.len();

    gt.counts = Counts {
        exact_groups: gt.exact_duplicate_groups.len(),
        exact_redundant_copies,
        similar_clusters_recompress,
        similar_clusters_geometric,
        geometric_variants,
        sibling_pairs: gt.should_not_group.len(),
        unique_files: gt.unique_files.len(),
        hygiene_items,
        total_files: total,
    };
}
