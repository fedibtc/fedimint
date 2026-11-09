//! Windows over the per-day volume counters that modules keep.

/// The days a volume window covers, `first_day..end_day`, ending with the
/// current day.
pub struct VolumeWindow {
    pub first_day: u64,
    pub end_day: u64,
}

impl VolumeWindow {
    pub fn new(today: u64, days: u64) -> Self {
        Self {
            first_day: (today + 1).saturating_sub(days),
            end_day: today + 1,
        }
    }

    /// Whether counting covered the whole window. `start` is the clock value,
    /// in `units_per_day` units, when counting started; 0 means the clock had
    /// not started, so counting started when the federation formed.
    pub fn is_complete(&self, start: Option<u64>, units_per_day: u64) -> bool {
        match start {
            None => false,
            Some(0) => true,
            Some(start) => start <= self.first_day * units_per_day,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VolumeWindow;

    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

    #[test]
    fn volume_window_ends_with_the_current_day() {
        let window = VolumeWindow::new(100, 7);
        assert_eq!((window.first_day, window.end_day), (94, 101));

        // A window longer than the clock's history starts at day zero.
        let window = VolumeWindow::new(3, 7);
        assert_eq!((window.first_day, window.end_day), (0, 4));
    }

    #[test]
    fn volume_window_is_complete_only_if_counting_covered_it() {
        let window = VolumeWindow::new(100, 7);
        let first_second = 94 * SECONDS_PER_DAY;

        assert!(!window.is_complete(None, SECONDS_PER_DAY));
        assert!(window.is_complete(Some(0), SECONDS_PER_DAY));
        assert!(window.is_complete(Some(first_second), SECONDS_PER_DAY));
        // Counting that started during the first day missed part of it.
        assert!(!window.is_complete(Some(first_second + 1), SECONDS_PER_DAY));

        // A young federation's window reaches back to day zero, so only
        // counting since formation covers it.
        let young = VolumeWindow::new(3, 7);
        assert!(young.is_complete(Some(0), SECONDS_PER_DAY));
        assert!(!young.is_complete(Some(1), SECONDS_PER_DAY));
    }
}
