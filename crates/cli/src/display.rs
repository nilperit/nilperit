//! Sizes and times for a person.

/// A size in bytes: `1.5 MiB`.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A time in milliseconds since 1970 as `2023-11-14 22:13`, in UTC.
///
/// The conversion from days to a date is the algorithm of Howard Hinnant for the
/// proleptic Gregorian calendar. It works for every `i64` that fits in a year of 9
/// digits, which is more than a time in the format can have in practice. For a time
/// outside that range it shows `-`.
pub fn time(milliseconds: i64) -> String {
    let seconds = milliseconds.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    if !(-100_000_000..=100_000_000).contains(&days) {
        return "-".into();
    }
    // Days since 1970-01-01 to a civil date.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        second_of_day / 3600,
        second_of_day % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_are_short_for_a_person() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1024), "1.0 KiB");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(size(3 * 1024 * 1024 * 1024), "3.0 GiB");
        // 2^64 bytes are 2^24 TiB.
        assert_eq!(size(u64::MAX), "16777216.0 TiB");
    }

    #[test]
    fn times_are_utc() {
        // The expected values come from Python's `datetime` (not from this code).
        for (milliseconds, shown) in [
            (0, "1970-01-01 00:00"),
            (1_700_000_000_000, "2023-11-14 22:13"),
            (1_709_164_800_000, "2024-02-29 00:00"),
            (4_102_444_800_000, "2100-01-01 00:00"),
            (-86_400_000, "1969-12-31 00:00"),
            (-1, "1969-12-31 23:59"),
            (951_782_400_000, "2000-02-29 00:00"),
            (1_234_567_890_123, "2009-02-13 23:31"),
        ] {
            assert_eq!(time(milliseconds), shown, "{milliseconds}");
        }
    }

    #[test]
    fn a_time_that_is_out_of_range_is_a_dash() {
        assert_eq!(time(i64::MAX), "-");
        assert_eq!(time(i64::MIN), "-");
    }
}
