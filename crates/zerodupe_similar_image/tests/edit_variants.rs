//! Variantes de edición (D-011): recorte central 80% y rotación leve ±3° con
//! lienzo expandido en blanco. Validadas con el corpus ground-truth el
//! 2026-06-12 (crops a distancia 0.0–2.7, rotaciones a 0.0–2.0). Solo el
//! modo `Full` las genera.

use zerodupe_core::FileCandidate;
use zerodupe_similar::detect_similars;
use zerodupe_similar_image::{
    GeometricInvariance, ImagePHashDetector, fingerprint_image, rotate_expand_white,
};

fn make_noise_image(seed: u64, width: u32, height: u32) -> image::RgbImage {
    let mut state = seed;
    let mut img = image::RgbImage::new(width, height);
    for y in 0..height {
        for x in 0..width {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            img.put_pixel(
                x,
                y,
                image::Rgb([
                    (state >> 56) as u8,
                    (state >> 48) as u8,
                    (state >> 40) as u8,
                ]),
            );
        }
    }
    img
}

fn candidate(path: &std::path::Path) -> FileCandidate {
    FileCandidate {
        path: camino::Utf8PathBuf::from_path_buf(path.to_path_buf()).expect("utf8"),
        size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
    }
}

#[test]
fn center_crop_detected_only_with_full() {
    let dir = tempfile::tempdir().unwrap();
    let img = make_noise_image(42, 200, 200);
    // Mismo rect que la variante interna: (w/10, h/10, w·8/10, h·8/10).
    let cropped = image::DynamicImage::ImageRgb8(img.clone())
        .crop_imm(20, 20, 160, 160)
        .to_rgb8();
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_crop80.png");
    img.save(&pa).unwrap();
    cropped.save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let mirror = ImagePHashDetector::new();
    let report_mirror = detect_similars(&files, &[&mirror], None, None, None);
    assert!(
        report_mirror.groups.is_empty(),
        "MirrorFlip no alcanza un recorte central (es trabajo de la variante de edición)"
    );

    let full = ImagePHashDetector::new().with_invariance(GeometricInvariance::Full);
    let report_full = detect_similars(&files, &[&full], None, None, None);
    assert_eq!(
        report_full.groups.len(),
        1,
        "Full debe agrupar una imagen con su recorte central 80%"
    );
}

#[test]
fn slight_rotation_detected_only_with_full() {
    let dir = tempfile::tempdir().unwrap();
    let img = image::DynamicImage::ImageRgb8(make_noise_image(77, 240, 180));
    // La copia "enderezada en el editor": +3° con lienzo expandido blanco.
    let rotated = rotate_expand_white(&img, 3.0);
    let pa = dir.path().join("a.png");
    let pb = dir.path().join("a_rot3.png");
    img.save(&pa).unwrap();
    rotated.save(&pb).unwrap();
    let files = vec![candidate(&pa), candidate(&pb)];

    let mirror = ImagePHashDetector::new();
    let report_mirror = detect_similars(&files, &[&mirror], None, None, None);
    assert!(
        report_mirror.groups.is_empty(),
        "MirrorFlip no alcanza una rotación de 3°"
    );

    let full = ImagePHashDetector::new().with_invariance(GeometricInvariance::Full);
    let report_full = detect_similars(&files, &[&full], None, None, None);
    assert_eq!(
        report_full.groups.len(),
        1,
        "Full debe agrupar una imagen con su copia rotada 3° (ambas direcciones: la \
         variante -3° de la rotada también apunta a la original)"
    );
}

#[test]
fn rotate_expand_white_geometry() {
    let img = image::DynamicImage::ImageRgb8(make_noise_image(9, 200, 100));
    let rot = rotate_expand_white(&img, 3.0);
    // El lienzo crece para contener el marco rotado.
    assert!(rot.width() > 200 && rot.height() > 100);
    // Las esquinas quedan blancas (cuñas fuera del marco original).
    let rgb = rot.to_rgb8();
    assert_eq!(rgb.get_pixel(0, 0).0, [255, 255, 255]);
    assert_eq!(
        rgb.get_pixel(rot.width() - 1, rot.height() - 1).0,
        [255, 255, 255]
    );
}

#[test]
fn degenerate_edit_variant_is_skipped_not_fatal() {
    // Centro uniforme con borde texturizado: el recorte central 80% es casi
    // liso (hash degenerado) aunque la imagen completa es válida. El gate
    // debe descartar esa variante sin tumbar el fingerprint completo.
    let dir = tempfile::tempdir().unwrap();
    let noise = make_noise_image(123, 256, 256);
    let mut img = image::RgbImage::from_pixel(256, 256, image::Rgb([200, 200, 200]));
    for y in 0..256u32 {
        for x in 0..256u32 {
            if !(24..232).contains(&x) || !(24..232).contains(&y) {
                img.put_pixel(x, y, *noise.get_pixel(x, y));
            }
        }
    }
    let p = dir.path().join("borde.png");
    img.save(&p).unwrap();

    let fp = fingerprint_image(&p, GeometricInvariance::Full);
    assert!(
        fp.is_ok(),
        "una variante de edición degenerada no debe invalidar el fingerprint: {fp:?}"
    );
}
