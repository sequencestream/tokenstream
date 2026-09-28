//! Signed UTC epoch-microsecond encoding shared by every storage backend.
//!
//! Repository boundaries exchange timestamps with the database as signed 64-bit
//! microseconds since the Unix epoch and convert to UTC date-time values in the
//! domain. Keeping the encoding in one place makes SQLite and PostgreSQL behave
//! identically, including for instants before 1970-01-01T00:00:00Z.

use chrono::{DateTime, Utc};

use super::RepositoryError;

/// Encodes a UTC date-time as signed microseconds since the Unix epoch.
///
/// The result is negative for instants before 1970-01-01T00:00:00Z. The full
/// range of a UTC date-time fits in `i64` at microsecond precision.
pub fn to_epoch_micros(value: DateTime<Utc>) -> i64 {
    value.timestamp_micros()
}

/// Decodes signed epoch microseconds into a UTC date-time.
///
/// Values outside the representable UTC date-time range are rejected as invalid
/// stored data instead of being silently truncated or coerced.
pub fn from_epoch_micros(micros: i64) -> Result<DateTime<Utc>, RepositoryError> {
    DateTime::from_timestamp_micros(micros).ok_or(RepositoryError::InvalidStoredData)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone, Utc};

    use super::{from_epoch_micros, to_epoch_micros};
    use crate::persistence::RepositoryError;

    #[test]
    fn encodes_negative_micros_before_the_epoch() {
        let instant = Utc
            .with_ymd_and_hms(1969, 12, 31, 23, 59, 59)
            .single()
            .expect("valid timestamp")
            + Duration::microseconds(999_999);
        assert_eq!(to_epoch_micros(instant), -1);
    }

    #[test]
    fn round_trips_sub_second_precision() {
        let instant = Utc
            .with_ymd_and_hms(2001, 9, 9, 1, 46, 40)
            .single()
            .expect("valid timestamp")
            + Duration::microseconds(555);
        let encoded = to_epoch_micros(instant);
        assert_eq!(encoded, 1_000_000_000_000_555);
        assert_eq!(from_epoch_micros(encoded).expect("decodable"), instant);
    }

    #[test]
    fn round_trips_the_epoch() {
        let instant = Utc
            .with_ymd_and_hms(1970, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp");
        assert_eq!(to_epoch_micros(instant), 0);
        assert_eq!(from_epoch_micros(0).expect("decodable"), instant);
    }

    #[test]
    fn rejects_micros_outside_the_representable_range() {
        assert_eq!(
            from_epoch_micros(i64::MAX),
            Err(RepositoryError::InvalidStoredData)
        );
        assert_eq!(
            from_epoch_micros(i64::MIN),
            Err(RepositoryError::InvalidStoredData)
        );
    }
}
