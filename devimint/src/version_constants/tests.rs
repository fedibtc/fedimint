use super::{reported_fedimintd_version, version_with_vendor};

#[test]
fn version_with_vendor_requires_exact_optional_identity() {
    let upstream = semver::Version::parse("0.11.1-rc.1").expect("valid version");
    let reported_upstream = semver::Version::parse("0.11.1-rc.1").expect("valid version");
    let reported_fedi = semver::Version::parse("0.11.1-rc.1+fedi").expect("valid version");
    let reported_acme = semver::Version::parse("0.11.1-rc.1+acme").expect("valid version");

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
        reported_acme
    );
}

#[test]
fn version_with_vendor_rejects_invalid_build_metadata() {
    let upstream = semver::Version::parse("0.11.1").expect("valid version");

    assert!(version_with_vendor(upstream.clone(), Some("")).is_err());
    assert!(version_with_vendor(upstream, Some("not valid")).is_err());
}

#[test]
fn fedimintd_reports_its_dkg_line_from_0_13() {
    let reported = |version: &str| {
        reported_fedimintd_version(semver::Version::parse(version).expect("valid version"))
            .expect("valid version")
            .to_string()
    };

    assert_eq!(reported("0.13.1-alpha+fedi"), "0.12.0+fedi");
    assert_eq!(reported("0.13.0-alpha"), "0.12.0");
    assert_eq!(reported("0.12.2-alpha+fedi"), "0.12.2-alpha+fedi");
    assert_eq!(reported("0.11.1-rc.1"), "0.11.1-rc.1");
}
