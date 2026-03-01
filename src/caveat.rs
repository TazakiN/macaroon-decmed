use crate::crypto;
use crate::error::MacaroonError;
use crate::ByteString;
use crate::Result;
use crypto::MacaroonKey;
use std::fmt::Debug;

/// Represents a caveat attached to a macaroon.
///
/// Caveats are conditions that restrict the authority conveyed by a macaroon.
/// In a DecMed access-control context, caveats can encode rules such as
/// `"patient_id = 12345"`, `"category = lab_results"`, or
/// `"expires < 2026-04-01T00:00Z"`.
///
/// - `FirstParty` caveats are verified locally by the macaroon verifier.
/// - `ThirdParty` caveats require external discharge macaroons for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    FirstParty(FirstParty),
    ThirdParty(ThirdParty),
}

/// A first-party caveat containing a predicate string.
///
/// The predicate is evaluated by the verifier — either via exact string
/// match ([`Verifier::satisfy_exact`](crate::Verifier::satisfy_exact)) or
/// a user-supplied function
/// ([`Verifier::satisfy_general`](crate::Verifier::satisfy_general)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstParty {
    predicate: ByteString,
}

impl FirstParty {
    /// Returns a clone of this caveat's predicate.
    pub fn predicate(&self) -> ByteString {
        self.predicate.clone()
    }
}

/// A third-party caveat that must be verified by an external service.
///
/// Contains the caveat ID, encrypted verifier ID (which encodes the
/// third-party's key), and a location hint pointing to the service that
/// can issue the corresponding discharge macaroon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThirdParty {
    id: ByteString,
    verifier_id: ByteString,
    location: String,
}

impl ThirdParty {
    /// Returns a clone of this caveat's identifier.
    pub fn id(&self) -> ByteString {
        self.id.clone()
    }

    /// Returns a clone of the encrypted verifier ID.
    pub fn verifier_id(&self) -> ByteString {
        self.verifier_id.clone()
    }

    /// Returns a clone of this caveat's location string.
    pub fn location(&self) -> String {
        self.location.clone()
    }
}

impl Caveat {
    /// Computes the signature contribution of this caveat.
    ///
    /// For first-party caveats: `HMAC(key, predicate)`.
    /// For third-party caveats: `HMAC2(key, verifier_id, id)`.
    pub fn sign(&self, key: &MacaroonKey) -> MacaroonKey {
        match self {
            Self::FirstParty(fp) => crypto::hmac(key, &fp.predicate),
            Self::ThirdParty(tp) => crypto::hmac2(key, &tp.verifier_id, &tp.id),
        }
    }
}

/// Creates a new first-party caveat with the given predicate.
pub fn new_first_party(predicate: ByteString) -> Caveat {
    Caveat::FirstParty(FirstParty { predicate })
}

/// Creates a new third-party caveat with the given ID, verifier ID, and
/// location.
pub fn new_third_party(id: ByteString, verifier_id: ByteString, location: &str) -> Caveat {
    Caveat::ThirdParty(ThirdParty {
        id,
        verifier_id,
        location: String::from(location),
    })
}

/// Builder for constructing caveat values from deserialized fields.
#[derive(Default)]
pub struct CaveatBuilder {
    id: Option<ByteString>,
    verifier_id: Option<ByteString>,
    location: Option<String>,
}

impl CaveatBuilder {
    /// Creates a new, empty caveat builder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the caveat identifier.
    pub fn add_id(&mut self, id: ByteString) {
        self.id = Some(id);
    }

    /// Returns `true` if an identifier has been set.
    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    /// Sets the encrypted verifier ID (third-party caveats only).
    pub fn add_verifier_id(&mut self, vid: ByteString) {
        self.verifier_id = Some(vid);
    }

    /// Sets the location hint (third-party caveats only).
    pub fn add_location(&mut self, location: String) {
        self.location = Some(location);
    }

    /// Returns `true` if a location has been set.
    pub fn has_location(&self) -> bool {
        self.location.is_some()
    }

    /// Builds the caveat, returning an error if required fields are missing.
    ///
    /// - If only `id` is set → first-party caveat.
    /// - If `id`, `verifier_id`, and `location` are all set → third-party caveat.
    /// - Otherwise → error.
    pub fn build(self) -> Result<Caveat> {
        let id = match self.id {
            Some(id) => id,
            None => return Err(MacaroonError::IncompleteCaveat("no identifier found")),
        };
        match (self.verifier_id, self.location) {
            (None, None) => Ok(new_first_party(id)),
            (Some(vid), Some(loc)) => Ok(new_third_party(id, vid, &loc)),
            (None, Some(_)) => Err(MacaroonError::IncompleteCaveat("no verifier ID found")),
            (Some(_), None) => Err(MacaroonError::IncompleteCaveat("no location found")),
        }
    }
}
