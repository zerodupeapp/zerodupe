//! El keeper de una limpieza anterior es el único superviviente en disco de
//! su grupo: una pasada posterior de similares no debe poder mandarlo a
//! cuarentena (decisión de René 2026-06-12, 32 casos en la prueba manual).

use zerodupe_workflow::{Workflow, WorkflowAction, WorkflowState};

/// Textura pseudoaleatoria determinista en bloques de 8×8 (sobrevive el
/// downscale del pHash; un gradiente liso da hash degenerado). `size` permite
/// crear una variante de mayor resolución que gane el keeper scoring.
fn textured_image(size: u32, brightness: u8) -> image::RgbImage {
    let mut seed: u64 = 0x5DEECE66D;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (seed >> 33) as u8
    };
    let mut blocks = [[0u8; 8]; 8];
    for row in &mut blocks {
        for v in row.iter_mut() {
            *v = next();
        }
    }
    let block = size / 8;
    image::RgbImage::from_fn(size, size, |x, y| {
        let v = blocks[(y / block) as usize][(x / block) as usize].saturating_add(brightness);
        image::Rgb([v, v, v])
    })
}

#[test]
fn prior_exact_keeper_survives_later_similar_scan() {
    let tmp = tempfile::tempdir().unwrap();
    // El tempdir empieza con "." y el discovery omite ocultos.
    let root = tmp.path().join("corpus");
    std::fs::create_dir(&root).unwrap();

    // Dos copias byte-idénticas (grupo exacto) + una variante perceptual de
    // mayor resolución, que sin protección ganaría el keeper scoring del
    // grupo similar y mandaría al keeper exacto a cuarentena.
    textured_image(64, 0).save(root.join("a.png")).unwrap();
    std::fs::copy(root.join("a.png"), root.join("a_copy.png")).unwrap();
    textured_image(128, 5).save(root.join("b.png")).unwrap();

    // ── Corrida 1: limpieza exacta ──
    let mut wf = Workflow::new();
    wf.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf.advance(WorkflowAction::StartScan).unwrap();
    assert!(matches!(wf.state(), WorkflowState::ReviewingExact { .. }));

    let exact_keeper_index = {
        let report = wf.exact_report().expect("debe existir exact_report");
        assert_eq!(
            report.confirmed_groups.len(),
            1,
            "a.png y a_copy.png son un grupo exacto"
        );
        report.confirmed_groups[0].keeper_index
    };
    wf.advance(WorkflowAction::ConfirmClean {
        keepers: vec![exact_keeper_index],
    })
    .unwrap();
    assert!(matches!(wf.state(), WorkflowState::Complete { .. }));
    wf.advance(WorkflowAction::Reset).unwrap();

    // Sobrevive exactamente una de las dos copias: ese es el keeper exacto.
    let survivor = ["a.png", "a_copy.png"]
        .iter()
        .map(|n| root.join(n))
        .find(|p| p.exists())
        .expect("el keeper exacto debe seguir en disco");

    // El journal de la cuarentena registró al keeper.
    let q = zerodupe_safety::Quarantine::open(root.join("zerodupe_quarantine").as_path()).unwrap();
    let kept = q.kept_files().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].as_std_path(), survivor.as_path());
    drop(q);

    // ── Corrida 2: escaneo de similares sobre la misma raíz ──
    let mut wf2 = Workflow::new();
    wf2.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf2.advance(WorkflowAction::StartSimilarScan).unwrap();
    assert!(matches!(
        wf2.state(),
        WorkflowState::ReviewingSimilar { .. }
    ));

    let keeper_index = {
        let report = wf2.similar_report().expect("debe existir similar_report");
        assert_eq!(
            report.groups.len(),
            1,
            "survivor y b.png forman un grupo similar"
        );
        let group = &report.groups[0];
        assert_eq!(group.files.len(), 2);
        // El keeper del grupo similar DEBE ser el keeper de la limpieza
        // anterior, aunque b.png tenga mejor keeper score (más resolución).
        assert_eq!(
            group.files[group.keeper_index].path.as_std_path(),
            survivor.as_path(),
            "el keeper previo debe quedar fijado como keeper del grupo similar"
        );
        group.keeper_index
    };

    wf2.advance(WorkflowAction::ConfirmClean {
        keepers: vec![keeper_index],
    })
    .unwrap();
    assert!(matches!(wf2.state(), WorkflowState::Complete { .. }));

    // El keeper previo sigue en disco; la variante se fue a cuarentena.
    assert!(
        survivor.exists(),
        "el keeper de la limpieza anterior nunca debe removerse"
    );
    assert!(!root.join("b.png").exists(), "la variante sí es removible");

    wf2.advance(WorkflowAction::Reset).unwrap();
}

#[test]
fn prior_keeper_is_unremovable_even_with_override() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("corpus");
    std::fs::create_dir(&root).unwrap();

    textured_image(64, 0).save(root.join("a.png")).unwrap();
    std::fs::copy(root.join("a.png"), root.join("a_copy.png")).unwrap();
    textured_image(128, 5).save(root.join("b.png")).unwrap();

    let mut wf = Workflow::new();
    wf.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf.advance(WorkflowAction::StartScan).unwrap();
    let exact_keeper_index = wf.exact_report().unwrap().confirmed_groups[0].keeper_index;
    wf.advance(WorkflowAction::ConfirmClean {
        keepers: vec![exact_keeper_index],
    })
    .unwrap();
    wf.advance(WorkflowAction::Reset).unwrap();

    let survivor = ["a.png", "a_copy.png"]
        .iter()
        .map(|n| root.join(n))
        .find(|p| p.exists())
        .unwrap();

    let mut wf2 = Workflow::new();
    wf2.advance(WorkflowAction::SelectFolder {
        path: root.to_string_lossy().to_string(),
    })
    .unwrap();
    wf2.advance(WorkflowAction::StartSimilarScan).unwrap();

    // Override adversarial: el usuario marca b.png como keeper, dejando al
    // keeper previo como candidato a remoción. El backstop debe protegerlo.
    let group = &wf2.similar_report().unwrap().groups[0];
    let b_index = group
        .files
        .iter()
        .position(|f| f.path.as_std_path() != survivor.as_path())
        .unwrap();
    wf2.advance(WorkflowAction::ConfirmClean {
        keepers: vec![b_index],
    })
    .unwrap();

    assert!(
        survivor.exists(),
        "ni un override de keeper puede mandar a cuarentena al keeper previo"
    );
    assert!(
        root.join("b.png").exists(),
        "el keeper elegido por el usuario también queda"
    );

    wf2.advance(WorkflowAction::Reset).unwrap();
}
