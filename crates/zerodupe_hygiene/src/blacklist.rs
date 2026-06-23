use camino::Utf8Path;
use zerodupe_platform::PlatformProfile;

/// Returns true if the path should NEVER be cleaned (absolute blacklist).
/// These are entities that can appear inside a scan target and must be protected.
pub fn is_blacklisted(path: &Utf8Path, _profile: &dyn PlatformProfile) -> bool {
    let path_str = path.as_str();
    let file_name = path.file_name().unwrap_or("");

    // VCS directories
    if path_str.contains("/.git/")
        || path_str.ends_with("/.git")
        || path_str.contains("/.hg/")
        || path_str.ends_with("/.hg")
        || path_str.contains("/.svn/")
        || path_str.ends_with("/.svn")
        || path_str.contains("/.bzr/")
        || path_str.ends_with("/.bzr")
    {
        return true;
    }

    // .nomedia (Android intentional marker)
    if file_name == ".nomedia" {
        return true;
    }

    // node_modules with sibling package.json or lockfile (live project)
    if path_str.contains("node_modules")
        && let Some(parent) = path.parent()
    {
        let siblings = [
            "package.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "package-lock.json",
        ];
        for sib in &siblings {
            if parent.join(sib).exists() {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerodupe_platform::mock::MockProfile;

    #[test]
    fn git_dir_blacklisted() {
        let profile = MockProfile::linux_like();
        assert!(is_blacklisted(
            Utf8Path::new("/target/.git/config"),
            &profile,
        ));
    }

    #[test]
    fn svn_dir_blacklisted() {
        let profile = MockProfile::linux_like();
        assert!(is_blacklisted(
            Utf8Path::new("/target/project/.svn/entries"),
            &profile,
        ));
    }

    #[test]
    fn nomedia_blacklisted() {
        let profile = MockProfile::linux_like();
        assert!(is_blacklisted(
            Utf8Path::new("/target/Pictures/.nomedia"),
            &profile,
        ));
    }

    #[test]
    fn regular_file_not_blacklisted() {
        let profile = MockProfile::linux_like();
        assert!(!is_blacklisted(
            Utf8Path::new("/target/Pictures/vacation.jpg"),
            &profile,
        ));
    }
}
