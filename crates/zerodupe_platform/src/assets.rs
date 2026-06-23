//! Compile-time TOML asset parsing.
//!
//! Each TOML file is embedded via `include_str!()` and parsed once
//! into a lazy static. Results are shared across all platform profiles
//! (all OS sections are always active).

use std::sync::LazyLock;

use serde::Deserialize;

use crate::{CanonicalRoot, JunkLocation, SystemExclude};

pub(crate) fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn parse_toml_patterns(toml_str: &str) -> Vec<(String, String)> {
    let value: toml::Value = toml_str
        .parse()
        .expect("failed to parse embedded TOML asset");
    let table = value.as_table().expect("embedded TOML must be a table");

    let mut entries = Vec::new();
    for (section, section_val) in table {
        if let Some(patterns) = section_val.get("patterns").and_then(|v| v.as_array()) {
            for p in patterns {
                let pattern = p.as_str().expect("pattern must be a string");
                entries.push((section.clone(), pattern.to_owned()));
            }
        }
    }
    entries
}

fn load_toml_canonical_roots() -> Vec<CanonicalRoot> {
    let toml = include_str!("../assets/canonical_roots.toml");
    parse_toml_patterns(toml)
        .into_iter()
        .map(|(section, pattern)| {
            let label = leak_str(format!("{pattern} (toml:{section})"));
            let pat = leak_str(pattern);
            CanonicalRoot {
                label,
                pattern: pat,
                score: 5,
            }
        })
        .collect()
}

fn load_toml_junk_locations() -> Vec<JunkLocation> {
    let toml = include_str!("../assets/junk_locations.toml");
    parse_toml_patterns(toml)
        .into_iter()
        .map(|(section, pattern)| {
            let label = leak_str(format!("{pattern} (toml:{section})"));
            let pat = leak_str(pattern);
            JunkLocation {
                label,
                pattern: pat,
                score: -50,
            }
        })
        .collect()
}

fn load_toml_system_excludes() -> Vec<SystemExclude> {
    let toml = include_str!("../assets/system_excludes.toml");
    parse_toml_patterns(toml)
        .into_iter()
        .map(|(section, pattern)| {
            let label = leak_str(format!("{pattern} (toml:{section})"));
            let pat = leak_str(pattern);
            let match_full_path = pat.contains('/') || pat.contains('\\');
            SystemExclude {
                label,
                pattern: pat,
                match_full_path,
            }
        })
        .collect()
}

pub(crate) fn toml_canonical_roots() -> &'static [CanonicalRoot] {
    static DATA: LazyLock<Vec<CanonicalRoot>> = LazyLock::new(load_toml_canonical_roots);
    &DATA
}

pub(crate) fn toml_junk_locations() -> &'static [JunkLocation] {
    static DATA: LazyLock<Vec<JunkLocation>> = LazyLock::new(load_toml_junk_locations);
    &DATA
}

pub(crate) fn toml_system_excludes() -> &'static [SystemExclude] {
    static DATA: LazyLock<Vec<SystemExclude>> = LazyLock::new(load_toml_system_excludes);
    &DATA
}

fn load_toml_protected_paths() -> Vec<String> {
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct PathsDoc {
        linux: Option<PathsSection>,
        macos: Option<PathsSection>,
        windows: Option<PathsSection>,
        user: Option<PathsSection>,
    }
    #[derive(Deserialize)]
    struct PathsSection {
        paths: Vec<String>,
    }

    let toml = include_str!("../assets/protected_paths.toml");
    let doc: PathsDoc = toml::from_str(toml).unwrap_or(PathsDoc {
        linux: None,
        macos: None,
        windows: None,
        user: None,
    });

    let mut paths = Vec::new();

    if let Some(ref user) = doc.user {
        paths.extend(user.paths.clone());
    }

    #[cfg(target_os = "linux")]
    if let Some(ref linux) = doc.linux {
        paths.extend(linux.paths.clone());
    }
    #[cfg(target_os = "macos")]
    if let Some(ref macos) = doc.macos {
        paths.extend(macos.paths.clone());
    }
    #[cfg(windows)]
    if let Some(ref windows) = doc.windows {
        paths.extend(windows.paths.clone());
    }

    paths
}

pub(crate) fn toml_protected_paths() -> &'static [String] {
    static DATA: LazyLock<Vec<String>> = LazyLock::new(load_toml_protected_paths);
    &DATA
}
