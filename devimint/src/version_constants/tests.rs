use super::version_with_vendor;

#[test]
fn version_with_vendor_requires_exact_optional_identity() {
    let upstream = semver::Version::parse("0.11.0-rc.1").expect("valid version");
    let reported_upstream = semver::Version::parse("0.11.0-rc.1").expect("valid version");
    let reported_fedi = semver::Version::parse("0.11.0-rc.1+fedi").expect("valid version");
    let reported_other = semver::Version::parse("0.11.0-rc.1+other").expect("valid version");

    assert_eq!(
        version_with_vendor(upstream.clone(), None).expect("valid upstream version"),
        reported_upstream
    );
    assert_eq!(
        version_with_vendor(upstream.clone(), Some("fedi")).expect("valid vendor"),
        reported_fedi
    );
    assert_ne!(
        version_with_vendor(upstream, Some("fedi")).expect("valid vendor"),
        reported_other
    );
}

#[test]
fn version_with_vendor_rejects_invalid_build_metadata() {
    let upstream = semver::Version::parse("0.11.0").expect("valid version");

    assert!(version_with_vendor(upstream.clone(), Some("")).is_err());
    assert!(version_with_vendor(upstream, Some("not valid")).is_err());
}
