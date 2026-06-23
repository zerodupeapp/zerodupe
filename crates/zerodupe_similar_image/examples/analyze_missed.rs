//! Herramienta de calibración del detector de similares. Mide distancias
//! combinadas (pHash + 0.7·dHash) de pares concretos contra los umbrales
//! adaptativos, y el piso de ruido de un corpus completo. Incluye un
//! prototipo 16×16 para comparar separación (análisis Ola 3, 2026-06-12).
//!
//! Modos:
//!   analyze_missed pairs <pairs.json>   — pares {a,b,transform}: d8, d16, umbral
//!   analyze_missed noise <list.json> <cutoff8>
//!       — lista de rutas (JSON array): histograma de distancias por pares
//!         (min-alignment para 8×8, canónico para 16×16) e imprime los pares
//!         con d8 ≤ cutoff para clasificarlos contra un ground truth.

use image_hasher::{HashAlg, HasherConfig};
use std::path::Path;
use zerodupe_similar::SimilarityDetector;
use zerodupe_similar_image::{GeometricInvariance, ImagePHashDetector};

fn hashers16() -> (image_hasher::Hasher, image_hasher::Hasher) {
    (
        HasherConfig::new()
            .hash_size(16, 16)
            .hash_alg(HashAlg::Median)
            .preproc_dct()
            .to_hasher(),
        HasherConfig::new()
            .hash_size(16, 16)
            .hash_alg(HashAlg::Gradient)
            .to_hasher(),
    )
}

fn hamming(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Bloques 16×16 (32B pHash + 32B dHash) de las 8 alineaciones D4.
fn blocks16(img: &image::DynamicImage) -> Vec<[u8; 64]> {
    let (hp, hd) = hashers16();
    let pair = |im: &image::DynamicImage| {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(hp.hash_image(im).as_bytes());
        b[32..].copy_from_slice(hd.hash_image(im).as_bytes());
        b
    };
    let img = if img.width().max(img.height()) > 1024 {
        img.thumbnail(1024, 1024)
    } else {
        img.clone()
    };
    vec![
        pair(&img),
        pair(&img.fliph()),
        pair(&img.flipv()),
        pair(&img.rotate90()),
        pair(&img.rotate180()),
        pair(&img.rotate270()),
        pair(&img.rotate90().fliph()),
        pair(&img.rotate270().fliph()),
    ]
}

/// Distancia combinada 16×16 (pHash + 0.7·dHash), mínimo sobre alineaciones
/// de `a` contra la canónica de `b`.
fn d16_min(a: &[[u8; 64]], b0: &[u8; 64]) -> f64 {
    a.iter()
        .map(|blk| {
            hamming(&blk[..32], &b0[..32]) as f64 + 0.7 * hamming(&blk[32..], &b0[32..]) as f64
        })
        .fold(f64::INFINITY, f64::min)
}

fn min_side(fp: &zerodupe_similar::FingerprintData) -> u64 {
    fp.metadata
        .get("min_side")
        .and_then(|v| v.as_u64())
        .unwrap_or(9999)
}

fn limit_for(ms: u64) -> f64 {
    if ms <= 128 {
        4.0
    } else if ms <= 256 {
        6.0
    } else if ms <= 512 {
        8.0
    } else {
        10.0
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let det = ImagePHashDetector::new().with_invariance(GeometricInvariance::Full);
    let mode = args[1].as_str();
    let input: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();

    match mode {
        "pairs" => {
            for p in input.as_array().unwrap() {
                let (a, b) = (p["a"].as_str().unwrap(), p["b"].as_str().unwrap());
                let t = p["transform"].as_str().unwrap_or("?");
                let (Ok(fa), Ok(fb)) =
                    (det.fingerprint(Path::new(a)), det.fingerprint(Path::new(b)))
                else {
                    println!("{t}\tERR fingerprint");
                    continue;
                };
                let d8 = (1.0 - det.similarity(&fa, &fb)) * 64.0;
                let ms = min_side(&fa).min(min_side(&fb));
                let (Ok(ia), Ok(ib)) = (image::open(a), image::open(b)) else {
                    println!("{t}\tERR open");
                    continue;
                };
                let d16 = d16_min(&blocks16(&ia), &blocks16(&ib)[0]);
                println!(
                    "{t}\td8={d8:.1}\tlimit={}\td16={d16:.1}\t(d16/4={:.1})\tmin_side={ms}\t{}",
                    limit_for(ms),
                    d16 / 4.0,
                    Path::new(b).file_name().unwrap().to_string_lossy()
                );
            }
        }
        "noise" => {
            let cutoff: f64 = args[3].parse().unwrap();
            let paths: Vec<&str> = input
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            use rayon::prelude::*;
            let fps: Vec<(String, zerodupe_similar::FingerprintData, [u8; 64])> = paths
                .par_iter()
                .filter_map(|p| {
                    let fp = det.fingerprint(Path::new(p)).ok()?;
                    let img = image::open(p).ok()?;
                    // Solo el bloque canónico 16×16: para el piso de ruido
                    // basta y evita 7 alineaciones extra por imagen.
                    let img = if img.width().max(img.height()) > 1024 {
                        img.thumbnail(1024, 1024)
                    } else {
                        img
                    };
                    let (hp, hd) = hashers16();
                    let mut b16 = [0u8; 64];
                    b16[..32].copy_from_slice(hp.hash_image(&img).as_bytes());
                    b16[32..].copy_from_slice(hd.hash_image(&img).as_bytes());
                    Some((p.to_string(), fp, b16))
                })
                .collect();
            eprintln!("fingerprinted {}/{}", fps.len(), paths.len());
            // Histograma combinado: bandas de 2 bits hasta 20 (escala 8×8) y
            // d16/4 en la misma escala para comparación directa.
            let mut h8 = [0u64; 11];
            let mut h16 = [0u64; 11];
            for i in 0..fps.len() {
                for j in (i + 1)..fps.len() {
                    let d8 = (1.0 - det.similarity(&fps[i].1, &fps[j].1)) * 64.0;
                    let d16 = d16_min(std::slice::from_ref(&fps[i].2), &fps[j].2) / 4.0;
                    let band = |d: f64| ((d / 2.0).floor() as usize).min(10);
                    h8[band(d8)] += 1;
                    h16[band(d16)] += 1;
                    if d8 <= cutoff {
                        let ms = min_side(&fps[i].1).min(min_side(&fps[j].1));
                        println!(
                            "PAIR\td8={d8:.1}\td16/4={d16:.1}\tmin_side={ms}\t{}\t{}",
                            fps[i].0, fps[j].0
                        );
                    }
                }
            }
            eprintln!("banda(bits 8x8-equiv)  pares_d8  pares_d16/4");
            for k in 0..11 {
                let lo = k * 2;
                eprintln!("{:>2}-{:<3} {:>10} {:>10}", lo, lo + 2, h8[k], h16[k]);
            }
        }
        other => panic!("modo desconocido: {other}"),
    }
}
