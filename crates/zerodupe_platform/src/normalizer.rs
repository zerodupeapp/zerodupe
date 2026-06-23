use camino::Utf8Path;

/// Normalize a path string for pattern matching.
///
/// This is the **single point** where path separators are handled.
/// All path-string matching in the codebase must go through this function.
///
/// Rules:
/// - Backslashes are converted to forward slashes (Windows compatibility).
/// - If the filesystem is case-insensitive, the result is lowercased.
pub fn normalize_for_match(path: &Utf8Path, case_sensitive: bool) -> String {
    let s = path.as_str().replace('\\', "/");
    if case_sensitive { s } else { s.to_lowercase() }
}

/// Extract the basename (file name) from a path, cross-platform.
/// Uses `Utf8Path::file_name()` which is separator-agnostic.
/// Prefer this over `rsplit('/')` everywhere.
pub fn basename(path: &Utf8Path) -> Option<&str> {
    path.file_name()
}

/// Extract the parent path, cross-platform.
/// Uses `Utf8Path::parent()` which is separator-agnostic.
pub fn parent(path: &Utf8Path) -> Option<&Utf8Path> {
    path.parent()
}

/// Extract the file extension (without dot), cross-platform.
pub fn extension(path: &Utf8Path) -> Option<&str> {
    path.extension()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_converts_backslashes() {
        let p = Utf8Path::new(r"C:\Users\rene\Pictures\IMG.jpg");
        let n = normalize_for_match(p, true);
        assert_eq!(n, "C:/Users/rene/Pictures/IMG.jpg");
    }

    #[test]
    fn normalize_lowercases_if_insensitive() {
        let p = Utf8Path::new("/Users/Rene/Pictures/IMG.JPG");
        let n = normalize_for_match(p, false);
        assert_eq!(n, "/users/rene/pictures/img.jpg");
    }

    #[test]
    fn normalize_preserves_case_if_sensitive() {
        let p = Utf8Path::new("/home/Rene/Pictures");
        let n = normalize_for_match(p, true);
        assert_eq!(n, "/home/Rene/Pictures");
    }

    #[test]
    fn basename_extracts_correctly() {
        // On Unix, Utf8Path::file_name() only splits on '/'. Use forward slashes
        // (which is what normalize_for_match produces from Windows paths).
        let p = Utf8Path::new("/Users/rene/file.txt");
        assert_eq!(basename(p), Some("file.txt"));
    }

    #[test]
    fn basename_from_normalized_windows_path() {
        // normalize_for_match converts \ to /, then basename works correctly
        let raw = Utf8Path::new(r"C:\Users\rene\file.txt");
        let normalized = normalize_for_match(raw, true);
        let p = Utf8Path::new(&normalized);
        assert_eq!(basename(p), Some("file.txt"));
    }

    #[test]
    fn extension_extracts_correctly() {
        let p = Utf8Path::new("/tmp/test.jpg");
        assert_eq!(extension(p), Some("jpg"));
    }
}
