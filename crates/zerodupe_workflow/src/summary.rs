use serde::{Deserialize, Serialize};
use zerodupe_core::ByteCompareReport;
use zerodupe_similar::SimilarityReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopGroup {
    pub name: String,
    pub ext: String,
    pub count: usize,
    pub size_bytes: u64,
    pub size_formatted: String,
    pub modified: String,
}

pub fn build_top_groups(report: &ByteCompareReport) -> Vec<TopGroup> {
    let mut groups: Vec<TopGroup> = report
        .confirmed_groups
        .iter()
        .map(|g| {
            let keeper = &g.files[g.keeper_index];
            let name = keeper.path.file_name().unwrap_or("unknown").to_string();
            let ext = keeper.path.extension().unwrap_or("").to_uppercase();
            let count = g.files.len();
            let size_bytes = g.size_bytes * (count as u64 - 1);

            TopGroup {
                name,
                ext,
                count,
                size_bytes,
                size_formatted: format_bytes(size_bytes),
                modified: "unknown".to_string(),
            }
        })
        .collect();

    groups.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    groups.truncate(5);
    groups
}

pub fn build_top_similar_groups(report: &SimilarityReport) -> Vec<TopGroup> {
    let mut groups: Vec<TopGroup> = report
        .groups
        .iter()
        .map(|g| {
            let keeper = &g.files[g.keeper_index];
            let name = keeper.path.file_name().unwrap_or("unknown").to_string();
            let ext = keeper.path.extension().unwrap_or("").to_uppercase();
            let count = g.files.len();
            let size_bytes: u64 = g
                .files
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != g.keeper_index)
                .map(|(_, f)| f.size_bytes)
                .sum();

            TopGroup {
                name,
                ext,
                count,
                size_bytes,
                size_formatted: format_bytes(size_bytes),
                modified: "unknown".to_string(),
            }
        })
        .collect();

    groups.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    groups.truncate(5);
    groups
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.2} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use camino::Utf8PathBuf;
    use zerodupe_core::{ByteCompareGroup, ByteCompareReport, FileCandidate};

    fn make_candidate(path: &str, size: u64) -> FileCandidate {
        FileCandidate {
            path: Utf8PathBuf::from(path),
            size_bytes: size,
        }
    }

    #[test]
    fn build_top_groups_sorts_by_reclaimable() {
        let report = ByteCompareReport {
            confirmed_groups: vec![
                ByteCompareGroup {
                    size_bytes: 100,
                    files: vec![
                        make_candidate("/a/small1.txt", 100),
                        make_candidate("/b/small1.txt", 100),
                    ],
                    false_positives: vec![],
                    keeper_index: 0,
                    keeper_path: Utf8PathBuf::from("/a/small1.txt"),
                },
                ByteCompareGroup {
                    size_bytes: 50_000_000,
                    files: vec![
                        make_candidate("/a/large.mp4", 50_000_000),
                        make_candidate("/b/large.mp4", 50_000_000),
                        make_candidate("/c/large.mp4", 50_000_000),
                    ],
                    false_positives: vec![],
                    keeper_index: 0,
                    keeper_path: Utf8PathBuf::from("/a/large.mp4"),
                },
            ],
            eliminated_by_compare: 0,
            false_positive_groups: 0,
            compare_errors: vec![],
            groups_trusted: 0,
            stale_cache_keys: vec![],
        };

        let groups = build_top_groups(&report);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].name, "large.mp4");
        assert_eq!(groups[0].ext, "MP4");
        assert_eq!(groups[0].count, 3);
        assert_eq!(groups[0].size_bytes, 100_000_000);
        assert_eq!(groups[0].size_formatted, "100.00 MB");
        assert_eq!(groups[1].name, "small1.txt");
        assert_eq!(groups[1].size_bytes, 100);
    }

    #[test]
    fn build_top_groups_truncates_to_five() {
        let make_group = |n: u64| ByteCompareGroup {
            size_bytes: n,
            files: vec![
                make_candidate(&format!("/a/file{n}.txt"), n),
                make_candidate(&format!("/b/file{n}.txt"), n),
            ],
            false_positives: vec![],
            keeper_index: 0,
            keeper_path: Utf8PathBuf::from(format!("/a/file{n}.txt")),
        };

        let report = ByteCompareReport {
            confirmed_groups: (1..=10).map(make_group).collect(),
            eliminated_by_compare: 0,
            false_positive_groups: 0,
            compare_errors: vec![],
            groups_trusted: 0,
            stale_cache_keys: vec![],
        };

        let groups = build_top_groups(&report);
        assert_eq!(groups.len(), 5);
        assert_eq!(groups[0].name, "file10.txt");
    }

    #[test]
    fn build_top_groups_empty_report() {
        let report = ByteCompareReport {
            confirmed_groups: vec![],
            eliminated_by_compare: 0,
            false_positive_groups: 0,
            compare_errors: vec![],
            groups_trusted: 0,
            stale_cache_keys: vec![],
        };
        let groups = build_top_groups(&report);
        assert!(groups.is_empty());
    }

    #[test]
    fn format_bytes_all_ranges() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1_500), "1.50 KB");
        assert_eq!(format_bytes(5_000_000), "5.00 MB");
        assert_eq!(format_bytes(2_500_000_000), "2.50 GB");
    }
}
