//! Benchmarks for image fingerprinting (zerodupe_similar_image).
//!
//! Measures the cost of perceptual hashing (pHash + dHash) which is the
//! dominant cost in the similar-images pipeline. Test images are generated
//! on the fly (structured gradient + shapes) so the benchmark is self-contained.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use image::{Rgb, RgbImage};
use zerodupe_similar_image::{GeometricInvariance, fingerprint_image};

/// Builds a structured image (diagonal gradient + a few rectangles) so the
/// perceptual hash has real DCT/gradient energy, like a photo would.
fn make_image(side: u32) -> RgbImage {
    let mut img = RgbImage::new(side, side);
    for y in 0..side {
        for x in 0..side {
            let t = (x + y) as f32 / (2.0 * side as f32);
            let v = (t * 255.0) as u8;
            img.put_pixel(x, y, Rgb([v, 255 - v, (x * 7 % 256) as u8]));
        }
    }
    // A few solid rectangles for higher-frequency structure.
    for k in 0..5u32 {
        let s = side / (3 + k);
        let ox = (k * 37) % side.max(1);
        let oy = (k * 53) % side.max(1);
        let color = Rgb([(k * 50) as u8, (255 - k * 40) as u8, (k * 30) as u8]);
        for y in oy..(oy + s).min(side) {
            for x in ox..(ox + s).min(side) {
                img.put_pixel(x, y, color);
            }
        }
    }
    img
}

fn bench_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("fingerprint_image");
    let dir = tempfile::tempdir().expect("tempdir");

    for &side in &[32u32, 128, 256, 512] {
        let label = format!("{side}x{side}");
        let path = dir.path().join(format!("{label}.png"));
        make_image(side).save(&path).expect("save png");

        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        group.throughput(Throughput::Bytes(size));
        group.bench_function(BenchmarkId::new("off", &label), |b| {
            b.iter(|| fingerprint_image(&path, GeometricInvariance::Off));
        });
        group.bench_function(BenchmarkId::new("mirror", &label), |b| {
            b.iter(|| fingerprint_image(&path, GeometricInvariance::MirrorFlip));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fingerprint);
criterion_main!(benches);
