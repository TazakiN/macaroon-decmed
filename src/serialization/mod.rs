pub mod macaroon_builder;
pub mod v1;
pub mod v2;
pub mod v2json;

/// Selects the serialization format for a macaroon token.
///
/// - `V1`: The original text-based format (compatible with libmacaroons).
/// - `V2`: A more compact binary format.
/// - `V2JSON`: A JSON representation of the V2 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    V1,
    V2,
    V2JSON,
}
