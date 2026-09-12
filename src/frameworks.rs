//! Optional names for framework identifiers.
//!
//! Isomer records ATT&CK and MBC identifiers from traits, but the catalogs are
//! maintained by Cleave's trait repository and are not bundled into this
//! binary. Keep this lookup conservative: callers always render the identifier,
//! and can add a name when a catalog is provided in the future.

/// Return a display name for a framework identifier when one is bundled.
///
/// No catalog is embedded currently, so identifiers remain the authoritative
/// display value and this returns `None`.
pub(crate) fn name(_id: &str) -> Option<&'static str> {
    None
}
