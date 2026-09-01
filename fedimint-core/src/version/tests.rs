use super::DkgVersion;

#[test]
fn dkg_version_ignores_patch_and_prerelease() {
    let stable = DkgVersion::parse("0.11.0+fedi").expect("valid version");
    let patch_prerelease = DkgVersion::parse("0.11.7-rc.2+fedi").expect("valid version");

    assert_eq!(
        stable.compatibility_version(),
        patch_prerelease.compatibility_version()
    );
    assert_eq!(stable.compatibility_version().to_string(), "0.11+fedi");
}

#[test]
fn dkg_version_requires_matching_minor_and_vendor() {
    let upstream = DkgVersion::parse("0.11.0").expect("valid version");
    let fedi = DkgVersion::parse("0.11.0+fedi").expect("valid version");
    let other_vendor = DkgVersion::parse("0.11.0+other").expect("valid version");
    let other_minor = DkgVersion::parse("0.12.0+fedi").expect("valid version");

    assert_ne!(
        upstream.compatibility_version(),
        fedi.compatibility_version()
    );
    assert_ne!(
        fedi.compatibility_version(),
        other_vendor.compatibility_version()
    );
    assert_ne!(
        fedi.compatibility_version(),
        other_minor.compatibility_version()
    );
}

#[test]
fn dkg_version_rejects_malformed_versions() {
    for version in ["", "0.11", "v0.11.0", "0.11.0+not valid"] {
        assert!(
            DkgVersion::parse(version).is_err(),
            "{version:?} should be rejected"
        );
    }
}
