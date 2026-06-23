//! `protect_prior_keepers`: los keepers de limpiezas anteriores se fijan como
//! keeper de su grupo similar y nunca quedan listados como removibles.

use std::collections::HashSet;

use zerodupe_core::FileCandidate;
use zerodupe_similar::{NearDuplicateGroup, SimilarityReport, protect_prior_keepers};

fn candidate(path: &str) -> FileCandidate {
    FileCandidate {
        path: path.into(),
        size_bytes: 100,
    }
}

fn group(paths: &[&str], keeper_index: usize) -> NearDuplicateGroup {
    let n = paths.len();
    let mut scores = vec![vec![0.9f64; n]; n];
    for (i, row) in scores.iter_mut().enumerate() {
        row[i] = 1.0;
    }
    NearDuplicateGroup {
        detector: "image-phash".to_string(),
        files: paths.iter().map(|p| candidate(p)).collect(),
        similarity_scores: scores,
        keeper_index,
        avg_similarity: 0.9,
        confidence: "high".to_string(),
    }
}

fn report(groups: Vec<NearDuplicateGroup>) -> SimilarityReport {
    SimilarityReport {
        groups,
        files_scanned: 0,
        files_skipped: 0,
        errors: Vec::new(),
    }
}

fn kept(paths: &[&str]) -> HashSet<String> {
    paths.iter().map(|p| (*p).to_string()).collect()
}

#[test]
fn no_kept_files_leaves_report_untouched() {
    let mut r = report(vec![group(&["/x/a.png", "/x/b.png"], 1)]);
    protect_prior_keepers(&mut r, &kept(&["/otro/lado.png"]));
    assert_eq!(r.groups.len(), 1);
    assert_eq!(r.groups[0].keeper_index, 1);
    assert_eq!(r.groups[0].files.len(), 2);
}

#[test]
fn kept_file_becomes_keeper() {
    // El scoring eligió b.png, pero a.png sobrevivió a una limpieza previa.
    let mut r = report(vec![group(&["/x/a.png", "/x/b.png"], 1)]);
    protect_prior_keepers(&mut r, &kept(&["/x/a.png"]));
    assert_eq!(r.groups[0].keeper_index, 0);
    assert_eq!(r.groups[0].files.len(), 2);
}

#[test]
fn current_keeper_wins_if_itself_kept() {
    let mut r = report(vec![group(&["/x/a.png", "/x/b.png", "/x/c.png"], 1)]);
    protect_prior_keepers(&mut r, &kept(&["/x/b.png"]));
    assert_eq!(r.groups[0].keeper_index, 1);
    assert_eq!(r.groups[0].files.len(), 3);
}

#[test]
fn extra_kept_files_are_dropped_from_group() {
    // Dos keepers previos en el mismo grupo: uno queda como keeper y el otro
    // sale del grupo (jamás puede listarse como removible). c.png sí queda.
    let mut r = report(vec![group(&["/x/a.png", "/x/b.png", "/x/c.png"], 2)]);
    protect_prior_keepers(&mut r, &kept(&["/x/a.png", "/x/b.png"]));
    let g = &r.groups[0];
    assert_eq!(g.files.len(), 2);
    let paths: Vec<&str> = g.files.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"/x/a.png"), "el keeper fijado queda");
    assert!(paths.contains(&"/x/c.png"), "el removible queda");
    assert!(
        !paths.contains(&"/x/b.png"),
        "el otro keeper previo sale del grupo"
    );
    assert_eq!(g.files[g.keeper_index].path.as_str(), "/x/a.png");
    // La matriz de similitud se reconstruye al nuevo tamaño.
    assert_eq!(g.similarity_scores.len(), 2);
    assert_eq!(g.similarity_scores[0].len(), 2);
}

#[test]
fn group_of_only_kept_files_is_removed() {
    let mut r = report(vec![
        group(&["/x/a.png", "/x/b.png"], 0),
        group(&["/y/c.png", "/y/d.png"], 0),
    ]);
    protect_prior_keepers(&mut r, &kept(&["/x/a.png", "/x/b.png"]));
    assert_eq!(
        r.groups.len(),
        1,
        "un grupo donde todos son keepers previos desaparece"
    );
    assert_eq!(r.groups[0].files[0].path.as_str(), "/y/c.png");
}
