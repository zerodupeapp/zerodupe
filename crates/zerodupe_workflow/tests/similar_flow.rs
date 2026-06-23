//! Test de integración del flujo de escaneo directo de imágenes similares
//! (`StartSimilarScan`), el camino que usa la GUI en modo "Imágenes similares".

use zerodupe_workflow::{Workflow, WorkflowAction, WorkflowState};

/// Genera una textura pseudoaleatoria determinista (LCG) con un offset de
/// brillo, para producir imágenes perceptualmente similares pero no
/// byte-idénticas. Un gradiente liso no sirve: el detector descarta hashes
/// degenerados de imágenes demasiado regulares.
fn textured_image(brightness: u8) -> image::RgbImage {
    let mut seed: u64 = 0x5DEECE66D;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    // Bloques de 8×8 con valor aleatorio: textura gruesa que sobrevive el
    // downscale del pHash.
    let mut blocks = [[0u8; 8]; 8];
    for row in &mut blocks {
        for v in row.iter_mut() {
            *v = next();
        }
    }
    image::RgbImage::from_fn(64, 64, |x, y| {
        let v = blocks[(y / 8) as usize][(x / 8) as usize].saturating_add(brightness);
        image::Rgb([v, v, v])
    })
}

#[test]
fn start_similar_scan_directly_finds_similar_images() {
    let tmp = tempfile::tempdir().unwrap();
    // El nombre del tempdir empieza con "." y el discovery omite ocultos:
    // usar un subdirectorio visible como raíz del escaneo.
    let root = tmp.path().join("corpus");
    std::fs::create_dir(&root).unwrap();
    textured_image(0).save(root.join("original.png")).unwrap();
    textured_image(5).save(root.join("variante.png")).unwrap();

    let mut wf = Workflow::new();
    wf.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf.advance(WorkflowAction::StartSimilarScan).unwrap();

    assert!(
        matches!(wf.state(), WorkflowState::ReviewingSimilar { .. }),
        "esperaba ReviewingSimilar, estado actual: {:?}",
        wf.state()
    );

    let report = wf.similar_report().expect("debe existir similar_report");
    assert_eq!(
        report.groups.len(),
        1,
        "las dos variantes forman un grupo — scanned={} skipped={} errors={:?} discovery_files={:?}",
        report.files_scanned,
        report.files_skipped,
        report.errors,
        wf.discovery().map(|d| d.summary.files),
    );
    assert_eq!(report.groups[0].files.len(), 2);

    // El modo similar directo NO ejecuta la fase de exactos.
    assert!(wf.exact_report().is_none());

    // El discovery fresco queda almacenado para que la GUI consulte stats.
    assert!(wf.discovery().is_some());

    // Limpia el resume state que el escaneo persiste.
    wf.advance(WorkflowAction::Reset).unwrap();
}

#[test]
fn start_similar_scan_requires_folder() {
    let mut wf = Workflow::new();
    let err = wf.advance(WorkflowAction::StartSimilarScan);
    assert!(err.is_err(), "sin SelectFolder previo debe fallar");
}

#[test]
fn confirm_clean_from_similar_quarantines_with_similar_session() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("corpus");
    std::fs::create_dir(&root).unwrap();
    textured_image(0).save(root.join("original.png")).unwrap();
    textured_image(5).save(root.join("variante.png")).unwrap();

    let mut wf = Workflow::new();
    wf.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf.advance(WorkflowAction::StartSimilarScan).unwrap();
    assert!(matches!(wf.state(), WorkflowState::ReviewingSimilar { .. }));

    let keeper_index = wf.similar_report().unwrap().groups[0].keeper_index;
    wf.advance(WorkflowAction::ConfirmClean {
        keepers: vec![keeper_index],
    })
    .unwrap();

    match wf.state() {
        WorkflowState::Complete {
            similar_files,
            exact_files,
            ..
        } => {
            assert_eq!(*similar_files, 1, "una variante movida a cuarentena");
            assert_eq!(*exact_files, 0, "el modo similar no limpia exactos");
        }
        other => panic!("esperaba Complete, estado: {other:?}"),
    }

    // La sesión de cuarentena debe quedar etiquetada como "similar".
    let qdir = root.join("zerodupe_quarantine");
    let q = zerodupe_safety::Quarantine::open(qdir.as_path()).unwrap();
    let sessions = q.list_sessions().unwrap();
    let similar_session = sessions
        .iter()
        .find(|s| s.mode == "similar")
        .expect("debe existir una sesión con modo similar");
    assert_eq!(similar_session.files.len(), 1);

    wf.advance(WorkflowAction::Reset).unwrap();
}
