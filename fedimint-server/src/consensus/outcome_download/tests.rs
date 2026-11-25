use std::time::{SystemTime, UNIX_EPOCH};

use super::{Duration, FailureReport, FailureSummary, REPORT_INTERVAL};

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000 + secs)
}

/// The first failure is reported at once; later ones only once per
/// interval, with every failure in between counted and the most common
/// kind named.
#[test]
fn failures_are_reported_once_per_interval_with_their_count() {
    let mut report = FailureReport::default();
    assert_eq!(
        report.record("no_address", at(0)),
        Some(FailureSummary {
            failure_kind: "no_address",
            failures: 1,
        })
    );
    for second in 1..300 {
        let kind = if second % 3 == 0 {
            "connect_timeout"
        } else {
            "no_address"
        };
        assert_eq!(report.record(kind, at(second)), None);
    }
    assert_eq!(
        report.record("connect_timeout", at(REPORT_INTERVAL.as_secs())),
        Some(FailureSummary {
            failure_kind: "no_address",
            failures: 300,
        })
    );
    assert_eq!(
        report.record("rejected", at(REPORT_INTERVAL.as_secs() + 1)),
        None
    );
}

#[test]
fn a_tie_names_the_kind_first_in_order() {
    let mut report = FailureReport::default();
    report.record("rejected", at(0));
    report.record("transport", at(1));
    report.record("connect_timeout", at(2));
    report.record("transport", at(3));
    assert_eq!(
        report
            .record("connect_timeout", at(REPORT_INTERVAL.as_secs()))
            .map(|summary| summary.failure_kind),
        Some("connect_timeout")
    );
}
