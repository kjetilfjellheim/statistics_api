use std::collections::{HashMap, HashSet};

use actix_web::{HttpRequest, http::header::HeaderMap};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use openssl::hash::MessageDigest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::debug;

/**
 * Signature algorithms.
 */
const SIGNATURE_ALGORITHM_RSA_PSS_SHA512: &str = "rsa-pss-sha512";
const SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256: &str = "rsa-v1_5-sha256";
const SIGNATURE_ALGORITHM_ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
const SIGNATURE_ALGORITHM_ECDSA_P384_SHA384: &str = "ecdsa-p384-sha384";
const SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
const SIGNATURE_ALGORITHM_HMAC_SHA256: &str = "hmac-sha256";

/**
 * Service for handling HTTP signatures.
 */
pub struct HttpSignaturesService {
    /**
     * A set of requirements for signature verification.
     */
    requirements: HashSet<VerificationRequirement>,
    /**
     * A map of keys used for signature verification. The key ID is used to look up the public key.
     * The key ID is expected to be in the `keyid` field of the signature input.
     */
    keys: HashMap<String, KeyParams>,
}

impl HttpSignaturesService {
    /**
     * Creates a new instance of `HttpSignaturesService`.
     *
     * # Arguments
     * `requirements`: A set of requirements for signature verification.
     * `keys`: A map of keys used for signature verification.
     *
     * # Returns
     * A new instance of `HttpSignaturesService`.  
     */
    pub fn new(requirements: HashSet<VerificationRequirement>, keys: HashMap<String, KeyParams>) -> Self {
        HttpSignaturesService { requirements, keys }
    }

    /**
     * Verifies the HTTP signature of a request.
     *
     * # Arguments
     * `headers`: The headers of the request.
     * `derive_elements`: The derived elements for signature verification.
     *
     * # Returns
     * A `Result` indicating success or failure of the verification.
     */
    pub fn verify_signature(&self, headers: &HashMap<String, String>, derive_elements: &DeriveElements) -> Result<(), HttpSignaturesError> {
        debug!("Verifying signature with headers: {:?}", headers);
        let signature = Self::get_signature(headers.get("signature").ok_or(HttpSignaturesError::MissingSignatureHeader)?)?;
        let signature = STANDARD.decode(signature.as_bytes()).map_err(|_| HttpSignaturesError::InvalidSignatureFormat)?;
        let signature_input = SignatureInput::new(
            headers,
            derive_elements,
            self.requirements.clone(),
            headers.contains_key("content-digest") || headers.contains_key("content-type") || headers.contains_key("content-length"),
        )?;
        let pkey = self.keys.get(&signature_input.keyid).ok_or(HttpSignaturesError::KeyNotFound { keyid: signature_input.keyid.clone() })?;
        Self::verify(signature_input.alg.as_str(), pkey, signature_input.get_signature_base().as_bytes(), &signature)?;
        Ok(())
    }

    /**
     * Extracts the signature from the signature header.
     * The expected format is sig=:jkjkjkjkjkjk:
     *
     * # Arguments
     * `signature`: The signature header value.
     *
     * # Returns
     * A `Result` containing the extracted signature or an error if the format is invalid.
     */
    fn get_signature(signature: &str) -> Result<String, HttpSignaturesError> {
        between(signature, "sig=:", ":").map(|s| s.to_string()).ok_or(HttpSignaturesError::InvalidSignatureFormat)
    }

    /**
     * Verifies the signature using the provided algorithm and public key.
     *
     * # Arguments
     * `algorithm`: The signature algorithm used (e.g., "RSA-PSS-SHA256").
     * `key_params`: The key parameters for verification.
     * `signature_base`: The base string to verify against the signature.
     * `signature`: The signature to verify.
     *
     * # Returns
     * A `Result` indicating success or failure of the verification.
     */
    fn verify(algorithm: &str, key_params: &KeyParams, signature_base: &[u8], signature: &[u8]) -> Result<(), HttpSignaturesError> {
        match algorithm.to_lowercase().as_str() {
            SIGNATURE_ALGORITHM_RSA_PSS_SHA512 => {
                if let Some(pkey) = &key_params.pkey {
                    let public_key = openssl::pkey::PKey::public_key_from_pem(pkey).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha512(), &public_key).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    verifier.update(signature_base).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    let result = verifier.verify(signature).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    if !result {
                        return Err(HttpSignaturesError::SignatureVerificationFailed);
                    }
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256 => {
                if let Some(pkey) = &key_params.pkey {
                    let public_key = openssl::pkey::PKey::public_key_from_pem(pkey).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    verifier.update(signature_base).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    let result = verifier.verify(signature).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    if !result {
                        return Err(HttpSignaturesError::SignatureVerificationFailed);
                    }
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 => {
                if let Some(pkey) = &key_params.pkey {
                    let public_key = openssl::pkey::PKey::public_key_from_pem(pkey).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &public_key).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    let result = verifier.verify_oneshot(signature, signature_base).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    if !result {
                        return Err(HttpSignaturesError::SignatureVerificationFailed);
                    }
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 => {
                if let Some(pkey) = &key_params.pkey {
                    let public_key = openssl::pkey::PKey::public_key_from_pem(pkey).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &public_key).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    let result = verifier.verify_oneshot(signature, signature_base).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    if !result {
                        return Err(HttpSignaturesError::SignatureVerificationFailed);
                    }
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            SIGNATURE_ALGORITHM_ED25519 => {
                if let Some(pkey) = &key_params.pkey {
                    let public_key = openssl::pkey::PKey::public_key_from_pem(pkey).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    let result = verifier.verify_oneshot(signature, signature_base).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                    if !result {
                        return Err(HttpSignaturesError::SignatureVerificationFailed);
                    }
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            SIGNATURE_ALGORITHM_HMAC_SHA256 => {
                if let Some(shared_secret) = &key_params.shared_secret {
                    let mut hmac = Hmac::<Sha256>::new_from_slice(shared_secret.as_bytes()).map_err(|_| HttpSignaturesError::MissingKeyParam)?;
                    hmac.update(signature_base);
                    hmac.verify_slice(signature).map_err(|_| HttpSignaturesError::SignatureVerificationFailed)?;
                } else {
                    return Err(HttpSignaturesError::MissingKeyParam);
                }
            }
            _ => return Err(HttpSignaturesError::UnsupportedAlgorithm { algorithm: algorithm.to_string() }),
        };
        Ok(())
    }
}

/**
 * Derived elements for HTTP signatures. These elements are used to derive the signature base string.
 * They are typically derived from the HTTP request method, target URI, and other request components.
 */
#[derive(Debug, Clone)]
pub struct DeriveElements {
    /**
     * The method derived element.
     */
    pub method: String,
    /**
     * The request target derived element.
     */
    pub request_target: String,
    /**
     * The path derived element.
     */
    pub path: String,
    /**
     * The target URI derived element.
     */
    pub target_uri: String,
    /**
     * The authority derived element.
     */
    pub authority: String,
    /**
     * The scheme derived element.
     */
    pub scheme: String,
    /**
     * The query derived element.
     */
    pub query: String,
}

impl DeriveElements {
    /**
     * Creates a new instance of `DeriveElements`.
     *
     * # Returns
     * A new instance of `DeriveElements`.
     */
    pub fn new(method: &str, request_target: &str, path: &str, target_uri: &str, authority: &str, scheme: &str, query: &str) -> Self {
        DeriveElements {
            method: method.to_string(),
            request_target: request_target.to_string(),
            path: path.to_string(),
            target_uri: target_uri.to_string(),
            authority: authority.to_string(),
            scheme: scheme.to_string(),
            query: query.to_string(),
        }
    }
}

impl From<&HttpRequest> for DeriveElements {
    /**
     * Converts an `HttpRequest` into `DeriveElements`.
     *
     * # Arguments
     * `http_request`: The HTTP request to derive elements from.
     *
     * # Returns
     * A new instance of `DeriveElements` derived from the HTTP request.
     */
    fn from(http_request: &HttpRequest) -> Self {
        let derive_elements = DeriveElements::new(
            http_request.method().as_str(),
            http_request.uri().path_and_query().map_or("/", |p| p.as_str()),
            http_request.uri().path(),
            http_request.uri().path_and_query().map_or("/", |p| p.as_str()),
            http_request.full_url().authority(),
            http_request.uri().scheme_str().unwrap_or("http"),
            http_request.uri().query().unwrap_or(""),
        );
        debug!("Derived Elements: {:?}", derive_elements);
        derive_elements
    }
}

/**
 * Key parameters for HTTP signatures.
 */
#[derive(Clone, Debug)]
pub struct KeyParams {
    /**
     * The public key used for signature verification.
     */
    pub pkey: Option<Vec<u8>>,
    /**
     * The shared secret used for hmac signature verification.
     */
    pub shared_secret: Option<String>,
}

impl KeyParams {
    /**
     * Creates a new instance of `KeyParams`.
     *
     * # Arguments
     * `pkey`: The public key used for signature verification.
     * `shared_secret`: The shared secret used for hmac signature verification.
     *
     * # Returns
     * A new instance of `KeyParams`.
     */
    pub fn new(pkey: Option<Vec<u8>>, shared_secret: Option<String>) -> Self {
        KeyParams { pkey, shared_secret }
    }
}

/**
 * Represents errors that can occur during HTTP signature processing.
 */
#[derive(Clone, Debug, PartialEq)]
pub enum HttpSignaturesError {
    /**
     * Error indicating that the signature format is invalid. This fails if the signature header is not of the following format:
     * sig=:<Base64 encoded signature>:
     * or if the signature could not be decoded.
     */
    InvalidSignatureFormat,
    /**
     * Error indicating that the key was not found. The missing keyid is provided.
     */
    KeyNotFound { keyid: String },
    /**
     * Error indicating that the expires is missing from the signature input. This is the expires= part of the signature input.
     */
    MissingExpiresTimestamp,
    /**
     * Error indicating that the signature header is missing.
     */
    MissingSignatureHeader,
    /**
     * Error indicating that the signature input header is missing.
     */
    MissingSignatureInputHeader,
    /**
     * Error indicating that the created timestamp is missing from the signature input. This is the created= part of the signature input.
     */
    MissingCreatedTimestamp,
    /**
     * Error indicating that a required header is missing from the signature input.
     */
    MissingRequiredHeader,
    /**
     * Error indicating that a required derived value is missing from the signature input. The derived values
     * are the values starting with '@' in the signature input.
     */
    MissingRequiredDerivedValue,
    /**
     * Error indicating that the algorithm is missing from the signature input. This is the alg= part of the signature input.
     */
    MissingAlgorithm,
    /**
     * Error indicating that the keyid is missing from the signature input. This is the keyid= part of the signature input.
     */
    MissingKeyId,
    /**
     * Error indicating that the request is missing a header included in the signature input.
     */
    MissingHeaderInRequest { name: String },
    /**
     * Error indicating that the signature input is empty. This means that no signature elements were found in the signature input.
     */
    NoSignatureElements,
    /**
     * Error indicating that the signature verification failed. This means that the signature could not be verified against the public key.
     * This can happen if the signature is invalid or if the public key is incorrect.
     */
    SignatureVerificationFailed,
    /**
     * Error indicating that the signature has expired. The expired timestamp is provided.
     */
    SignatureExpired { expired: usize },
    /**
     * Error indicating that the algorithm is unsupported. The unsupported algorithm is provided.
     */
    UnsupportedAlgorithm { algorithm: String },
    /**
     * Missing key parameter. For rsa, edcsa and ed22519 this is the public key.
     * For hmac this is the shared secret.
     */
    MissingKeyParam,
}

/**
 * Represents the requirements for verifying a signature.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationRequirement {
    /**
     * Represents a header that is required in the signature.
     */
    HeaderRequired { name: String },
    /**
     * Represents a header that is required in the signature if included in request.
     */
    HeaderRequiredIfIncludedInRequest { name: String },
    /**
     * Represents a header that is required in the signature if the body is present.
     */
    HeaderRequiredIfBodyPresent { name: String },
    /**
     * Is required required for the signature input.
     */
    CreatedRequired,
    /**
     * Is the expires required for the signature input.
     */
    ExpiresRequired,
    /**
     * Should the signature be checked for expiration.
     */
    CheckExpired,
    /**
     * Derived component that is required in the signature.
     */
    DerivedRequired { name: String },
}

/**
 * Elements of the signature input.
 */
#[derive(Debug)]
enum SignatureElementEnum {
    /**
     * Represents a header with a value.
     */
    HeaderString {
        name: String,
        value: String,
    },
    Method {
        value: String,
    },
    RequestTarget {
        value: String,
    },
    Query {
        value: String,
    },
    Path {
        value: String,
    },
    TargetUri {
        value: String,
    },
    Authority {
        value: String,
    },
    Scheme {
        value: String,
    },
}

/**
 * Represents the signature input.
 * Example: Signature-Input: sig=("date" "content-type" "content-digest" "@method" "@request-target");alg="rsa-pss-sha512";keyid="keyid";created=1754334782;expires=1754335082
 */
#[derive(Debug)]
struct SignatureInput {
    /**
     * The signature elements.
     * Example: sig=("date" "content-type" "content-digest" "@method" "@request-target")
     */
    sig: Vec<SignatureElementEnum>,
    /**
     * The algorithm used for the signature.
     * Example: alg="rsa-pss-sha512"
     */
    alg: String,
    /**
     * The key ID used for the signature.
     * Example: keyid="keyid"
     */
    keyid: String,
    /**
     * The timestamp when the signature was created.
     * Example: created=1754334782
     */
    created: Option<usize>,
    /**
     * The timestamp when the signature expires.
     * Example: expires=1754335082
     */
    expires: Option<usize>,
}

impl SignatureInput {
    /**
     * Parses a signature input string into a `SignatureInput` struct.
     *
     * #Arguments
     * `headers`: Header map containing the signature input.
     * `derive_elements`: The derived elements for signature verification.
     * `requirements`: Verification requirements.
     * `has_body`: Whether the request has a body.'
     *
     * #Returns
     * A `SignatureInput` struct containing the parsed elements.
     */
    fn new(headers: &HashMap<String, String>, derive_elements: &DeriveElements, requirements: HashSet<VerificationRequirement>, has_body: bool) -> Result<Self, HttpSignaturesError> {
        let signature_input = headers.get("signature-input").ok_or(HttpSignaturesError::MissingSignatureInputHeader)?;

        let (sig, alg, keyid, created, expires) = Self::get_signature_elements(headers, derive_elements, signature_input);
        Self::verify_created_requirement(&requirements, created)?;
        Self::verify_expires_requirement(&requirements, expires)?;
        Self::verify_empty_signature_elements(&sig)?;
        Self::verify_body_headers(&requirements, has_body, &sig)?;
        Self::verify_headers(&requirements, &sig)?;
        Self::verify_headers_if_included_in_request(&requirements, &sig, headers)?;
        Self::verify_derived(&requirements, &sig)?;
        Self::check_expired(requirements, expires)?;
        Self::verify_algorithm(&alg)?;
        Self::verify_keyid(&keyid)?;
        Self::verify_request_headers(headers, &sig)?;
        Ok(SignatureInput { sig, alg, keyid, created, expires })
    }

    /**
     * Returns a string representation of the signature parameters.
     *
     * This method constructs a string that includes all signature elements
     * formatted as "name=value" pairs, suitable for use in signature verification.
     */
    fn get_signature_params(&self) -> String {
        let mut signature_params = String::new();
        for element in &self.sig {
            if !signature_params.is_empty() {
                signature_params.push(' ');
            } else {
                signature_params.push('(');
            }
            match element {
                SignatureElementEnum::HeaderString { name, value: _ } => {
                    signature_params.push_str(&format!("\"{name}\""));
                }
                SignatureElementEnum::Method { value: _ } => {
                    signature_params.push_str("\"@method\"");
                }
                SignatureElementEnum::RequestTarget { value: _ } => {
                    signature_params.push_str("\"@request-target\"");
                }
                SignatureElementEnum::Query { value: _ } => {
                    signature_params.push_str("\"@query\"");
                }
                SignatureElementEnum::Path { value: _ } => {
                    signature_params.push_str("\"@path\"");
                }
                SignatureElementEnum::TargetUri { value: _ } => {
                    signature_params.push_str("\"@target-uri\"");
                }
                SignatureElementEnum::Authority { value: _ } => {
                    signature_params.push_str("\"@authority\"");
                }
                SignatureElementEnum::Scheme { value: _ } => {
                    signature_params.push_str("\"@scheme\"");
                }
            }
        }
        signature_params.push_str(");alg=\"");
        signature_params.push_str(&self.alg);
        signature_params.push_str("\";keyid=\"");
        signature_params.push_str(&self.keyid);
        signature_params.push_str("\";created=");
        signature_params.push_str(&self.created.map_or_else(|| "0".into(), |v| v.to_string()));
        signature_params.push_str(";expires=");
        signature_params.push_str(&self.expires.map_or_else(|| "0".into(), |v| v.to_string()));
        debug!("Signature Params: {}", signature_params);
        signature_params
    }

    /**
     * Returns the signature base string.
     *
     * This method constructs a string that includes all signature elements
     * formatted as "name: value" pairs, suitable for use in signature verification.
     */
    fn get_signature_base(&self) -> String {
        let mut signature_base = String::new();
        for element in &self.sig {
            if !signature_base.is_empty() {
                signature_base.push('\n');
            }
            match element {
                SignatureElementEnum::HeaderString { name, value } => {
                    signature_base.push_str(&format!("\"{name}\": {value}"));
                }
                SignatureElementEnum::Method { value } => {
                    signature_base.push_str(&format!("\"@method\": {value}"));
                }
                SignatureElementEnum::RequestTarget { value } => {
                    signature_base.push_str(&format!("\"@request-target\": {value}"));
                }
                SignatureElementEnum::Query { value } => {
                    signature_base.push_str(&format!("\"@query\": {value}"));
                }
                SignatureElementEnum::Path { value } => {
                    signature_base.push_str(&format!("\"@path\": {value}"));
                }
                SignatureElementEnum::TargetUri { value } => {
                    signature_base.push_str(&format!("\"@target-uri\": {value}"));
                }
                SignatureElementEnum::Authority { value } => {
                    signature_base.push_str(&format!("\"@authority\": {value}"));
                }
                SignatureElementEnum::Scheme { value } => {
                    signature_base.push_str(&format!("\"@scheme\": {value}"));
                }
            }
        }
        signature_base.push('\n');
        signature_base.push_str(&format!("\"@signature-params\": {}", self.get_signature_params()));
        debug!("Signature Base: \n{:?}", signature_base.as_bytes());
        signature_base
    }

    /**
     * Get the signature elements from the signature input string.
     *
     * #Arguments
     * `headers`: The headers of the request.
     * `derive_elements`: The derived elements from the request.
     * `signature_input`: The signature input string.
     *
     * # Returns
     * A tuple containing the updated signature elements, algorithm, key ID, created timestamp, and expires timestamp.
     */
    fn get_signature_elements(headers: &HashMap<String, String>, derive_elements: &DeriveElements, signature_input: &str) -> (Vec<SignatureElementEnum>, String, String, Option<usize>, Option<usize>) {
        let mut sig = Vec::new();
        let mut alg = String::new();
        let mut keyid = String::new();
        let mut created: Option<usize> = None;
        let mut expires: Option<usize> = None;
        for part in signature_input.split(';') {
            if part.starts_with("sig=(") {
                sig = Self::parse_signature_element(headers, derive_elements, part);
            } else if part.starts_with("alg=\"") {
                alg = between(part, "alg=\"", "\"").unwrap_or_default().to_string();
            } else if part.starts_with("keyid=\"") {
                keyid = between(part, "keyid=\"", "\"").unwrap_or_default().to_string();
            } else if part.starts_with("created=") {
                created = part.split('=').nth(1).and_then(|s| s.parse().ok());
            } else if part.starts_with("expires=") {
                expires = part.split('=').nth(1).and_then(|s| s.parse().ok());
            }
        }
        (sig, alg, keyid, created, expires)
    }

    /**
     * Parses a signature element from the signature input string.
     *
     * # Arguments
     * `headers`: The headers of the request.
     * `derive_elements`: The derived elements from the request.
     * `part`: The signature input string.
     *
     * # Returns
     * Vector of derived signatutre elements.
     */
    fn parse_signature_element(headers: &HashMap<String, String>, derive_elements: &DeriveElements, part: &str) -> Vec<SignatureElementEnum> {
        let mut sig = Vec::new();
        let value = between(part, "sig=(", ")").unwrap_or_default();
        for element in value.replace("\"", "").split_whitespace() {
            if element.starts_with('@') {
                if element == "@method" {
                    sig.push(SignatureElementEnum::Method { value: derive_elements.method.clone() });
                } else if element == "@request-target" {
                    sig.push(SignatureElementEnum::RequestTarget { value: derive_elements.request_target.clone() });
                } else if element == "@query" {
                    sig.push(SignatureElementEnum::Query { value: derive_elements.query.clone() });
                } else if element == "@path" {
                    sig.push(SignatureElementEnum::Path { value: derive_elements.path.clone() });
                } else if element == "@target-uri" {
                    sig.push(SignatureElementEnum::TargetUri { value: derive_elements.target_uri.clone() });
                } else if element == "@authority" {
                    sig.push(SignatureElementEnum::Authority { value: derive_elements.authority.clone() });
                } else if element == "@scheme" {
                    sig.push(SignatureElementEnum::Scheme { value: derive_elements.scheme.clone() });
                }
            } else {
                sig.push(SignatureElementEnum::HeaderString { name: element.to_string().to_lowercase(), value: headers.get(element).unwrap_or(&"".into()).to_string() });
            }
        }
        sig
    }

    /**
     * Verifies that the required headers are present in the request.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `sig`: The signature elements to verify.
     * `headers`: The headers of the request.
     *
     * # Returns
     * Ok if all required headers are present, otherwise an `HttpSignaturesError`.
     */
    fn verify_headers_if_included_in_request(requirements: &HashSet<VerificationRequirement>, sig: &[SignatureElementEnum], headers: &HashMap<String, String>) -> Result<(), HttpSignaturesError> {
        for requirement in requirements {
            if let VerificationRequirement::HeaderRequiredIfIncludedInRequest { name } = requirement {
                if !headers.contains_key(name) {
                    return Ok(());
                }
                if !sig.iter().any(|f| matches!(f, SignatureElementEnum::HeaderString { name: n, .. } if n == name)) {
                    return Err(HttpSignaturesError::MissingRequiredHeader);
                }
            }
        }
        Ok(())
    }

    /**
     * Verifies the created requirement for the signature input.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `created`: The created timestamp from the signature input.
     *
     * # Returns
     * Ok if the created requirement is satisfied, otherwise an `HttpSignaturesError`.
     */
    fn verify_created_requirement(requirements: &HashSet<VerificationRequirement>, created: Option<usize>) -> Result<(), HttpSignaturesError> {
        if requirements.contains(&VerificationRequirement::CreatedRequired) && created.is_none() {
            return Err(HttpSignaturesError::MissingCreatedTimestamp);
        }
        Ok(())
    }

    /**
     * Verifies the expires requirement for the signature input.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `expires`: The expires timestamp from the signature input.
     *
     * # Returns
     * Ok if the expires requirement is satisfied, otherwise an `HttpSignaturesError`.
     */
    fn verify_expires_requirement(requirements: &HashSet<VerificationRequirement>, expires: Option<usize>) -> Result<(), HttpSignaturesError> {
        if requirements.contains(&VerificationRequirement::ExpiresRequired) && expires.is_none() {
            return Err(HttpSignaturesError::MissingExpiresTimestamp);
        }
        Ok(())
    }

    /**
     * Verifies that the signature elements are not empty.
     *
     * # Arguments
     * `sig`: The signature elements to verify.
     *
     * # Returns
     * Ok if the signature elements are not empty, otherwise an `HttpSignaturesError`.
     */
    fn verify_empty_signature_elements(sig: &[SignatureElementEnum]) -> Result<(), HttpSignaturesError> {
        if sig.is_empty() {
            return Err(HttpSignaturesError::NoSignatureElements);
        }
        Ok(())
    }

    /**
     * Checks if the signature input meets the requirements for body headers.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `has_body`: Whether the request has a body.
     * `sig`: The signature elements to verify.
     *
     * # Returns
     * Ok if the body headers are verified, otherwise an `HttpSignaturesError`.
     */
    fn verify_body_headers(requirements: &HashSet<VerificationRequirement>, has_body: bool, sig: &[SignatureElementEnum]) -> Result<(), HttpSignaturesError> {
        if has_body {
            let body_reqs = requirements.iter().all(|f| match f {
                VerificationRequirement::HeaderRequiredIfBodyPresent { name } => sig.iter().any(|f| matches!(f, SignatureElementEnum::HeaderString { name: n, .. } if n == name)),
                _ => true,
            });
            if !body_reqs {
                return Err(HttpSignaturesError::MissingRequiredHeader);
            }
        }
        Ok(())
    }

    /**
     * Verifies that the required headers are present in the signature.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `sig`: The signature elements to verify.
     *
     * # Returns
     * Ok if all required headers are present, otherwise an `HttpSignaturesError`.
     */
    fn verify_headers(requirements: &HashSet<VerificationRequirement>, sig: &[SignatureElementEnum]) -> Result<(), HttpSignaturesError> {
        let header_reqs = requirements.iter().all(|f| match f {
            VerificationRequirement::HeaderRequired { name } => sig.iter().any(|f| matches!(f, SignatureElementEnum::HeaderString { name: n, .. } if n == name)),
            _ => true,
        });
        if !header_reqs {
            return Err(HttpSignaturesError::MissingRequiredHeader);
        }
        Ok(())
    }

    /**
     * Verifies that the derived values are present in the signature.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `sig`: The signature elements to verify.
     *
     * # Returns
     * Ok if all required derived values are present, otherwise an `HttpSignaturesError`.
     */
    fn verify_derived(requirements: &HashSet<VerificationRequirement>, sig: &[SignatureElementEnum]) -> Result<(), HttpSignaturesError> {
        let derived_reqs = requirements.iter().all(|f| match f {
            VerificationRequirement::DerivedRequired { name } => {
                let mut derived: bool = false;
                if name == "@method" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Method { .. }));
                }
                if name == "@request-target" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::RequestTarget { .. }));
                }
                if name == "@query" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Query { .. }));
                }
                if name == "@path" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Path { .. }));
                }
                if name == "@target-uri" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::TargetUri { .. }));
                }
                if name == "@authority" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Authority { .. }));
                }
                if name == "@scheme" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Scheme { .. }));
                }
                derived
            }
            _ => true,
        });
        if !derived_reqs {
            return Err(HttpSignaturesError::MissingRequiredDerivedValue);
        }
        Ok(())
    }

    /**
     * Checks if the signature has expired based on the requirements and expires timestamp.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `expires`: The expires timestamp from the signature input.
     *
     * # Returns
     * An `Ok(())` if the signature is valid, or an `HttpSignaturesError` if it is not.
     */
    fn check_expired(requirements: HashSet<VerificationRequirement>, expires: Option<usize>) -> Result<(), HttpSignaturesError> {
        if requirements.contains(&VerificationRequirement::CheckExpired) {
            if let Some(expiry) = expires {
                if expiry < chrono::Utc::now().timestamp() as usize {
                    return Err(HttpSignaturesError::SignatureExpired { expired: expiry });
                }
            }
        }
        Ok(())
    }

    /**
     * Verifies the algorithm used in the signature.
     *
     * # Arguments
     * `alg`: The algorithm string from the signature input.
     *
     * # Returns
     * An `Ok(())` if the algorithm is valid, or an `HttpSignaturesError` if it is not.
     */
    fn verify_algorithm(alg: &str) -> Result<(), HttpSignaturesError> {
        if alg.is_empty() {
            return Err(HttpSignaturesError::MissingAlgorithm);
        }
        Ok(())
    }

    /**
     * Verifies the key ID in the signature.
     *
     * # Arguments
     * `keyid`: The key ID string from the signature input.
     *
     * # Returns
     * An `Ok(())` if the key ID is valid, or an `HttpSignaturesError` if it is not.
     */
    fn verify_keyid(keyid: &str) -> Result<(), HttpSignaturesError> {
        if keyid.is_empty() {
            return Err(HttpSignaturesError::MissingKeyId);
        }
        Ok(())
    }

    /**
     * Verifies that the required headers are present in the request.
     *
     * # Arguments
     * `headers`: The headers of the request.
     * `sig`: The signature elements to verify.
     *
     * # Returns
     * Ok if all required headers are present, otherwise an `HttpSignaturesError`.
     */
    fn verify_request_headers(headers: &HashMap<String, String>, sig: &Vec<SignatureElementEnum>) -> Result<(), HttpSignaturesError> {
        for element in sig {
            if let SignatureElementEnum::HeaderString { name, .. } = element {
                if !headers.contains_key(name) {
                    return Err(HttpSignaturesError::MissingHeaderInRequest { name: name.clone() });
                }
            }
        }
        Ok(())
    }
}

/**
 * Extracts a substring from the input string between two delimiters.
 *
 * # Arguments
 * `source`: The source string to search within.
 * `start`: The starting delimiter.
 * `end`: The ending delimiter.
 *
 * # Returns
 * An `Option<&str>` containing the substring if found, otherwise `None`.
 */
fn between<'a>(source: &'a str, start: &'a str, end: &'a str) -> Option<&'a str> {
    if let Some(start_position) = source.find(start) {
        let start_position = start_position + start.len();
        let source = &source[start_position..];
        if let Some(end_position) = source.find(end) {
            return Some(&source[..end_position]);
        }
        return Some(source);
    }
    None
}

/**
 * Converts the headers to lowercase.
 *
 * # Arguments
 * `headers`: The headers to convert.
 * # Returns
 * A `HashMap<String, String>` containing the headers with lowercase keys.
 */
pub fn convert_headers_to_lowercase(headers: &HeaderMap) -> HashMap<String, String> {
    headers.iter().map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string())).collect()
}

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, HashSet},
        fs,
    };

    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA512, RsaKeyPair},
    };

    use super::*;

    #[tokio::test]
    async fn test_missing_signature() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let requirements: HashSet<VerificationRequirement> = HashSet::new();
        assert!(
            SignatureInput::new(
                &HashMap::from([
                    ("date".to_string(), "Tue".to_string()),
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"date\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .is_ok()
        );
        assert_eq!(SignatureInput::new(&HashMap::from([]), &derive_elements, requirements.clone(), false).unwrap_err(), HttpSignaturesError::MissingSignatureInputHeader);
    }

    #[tokio::test]
    async fn test_missing_created() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::CreatedRequired);
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";expires=1754335082".to_string()
                )]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingCreatedTimestamp
        );
    }

    #[tokio::test]
    async fn test_missing_expires() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::ExpiresRequired);
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782".to_string()
                )]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingExpiresTimestamp
        );
    }

    #[tokio::test]
    async fn test_missing_accept() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "accept".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0".to_string()
                )]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_missing_required_body_content_length() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-length".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("date".to_string(), "Tue".to_string()),
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    ("signature-input".to_string(), "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0".to_string())
                ]),
                &derive_elements,
                requirements.clone(),
                true
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_missing_required_header_date() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "date".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_missing_derived() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@method".into() });
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@request-target".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    ("signature-input".to_string(), "sig=(\"content-digest\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082".to_string())
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredDerivedValue
        );
    }

    #[tokio::test]
    async fn test_check_expired() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::CheckExpired);
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1554335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::SignatureExpired { expired: 1554335082 }
        );
    }

    #[tokio::test]
    async fn test_check_required_header_if_included_in_request_failure() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequiredIfIncludedInRequest { name: "accept".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("accept".to_string(), "application/json".to_string()),
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1554335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_check_required_header_if_included_in_request_success() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequiredIfIncludedInRequest { name: "accept".into() });
        assert!(
            SignatureInput::new(
                &HashMap::from([
                    ("accept".to_string(), "application/json".to_string()),
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"content-digest\" \"accept\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1554335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_full_test() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");

        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "date".into() });
        requirements.insert(VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".into() });
        requirements.insert(VerificationRequirement::ExpiresRequired);
        requirements.insert(VerificationRequirement::CreatedRequired);
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@method".into() });
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@request-target".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([
                    ("content-digest".to_string(), "ghghgh".to_string()),
                    (
                        "signature-input".to_string(),
                        "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1954335082".to_string()
                    )
                ]),
                &derive_elements,
                requirements.clone(),
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_between() {
        let signature_input = "sig=(\"created\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"123456789\";created=1754065546;expires=1754066746";
        assert_eq!(between(signature_input, "sig=(", ");"), Some("\"created\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\""));
        assert_eq!(between(signature_input, "alg=\"", "\";"), Some("rsa-pss-sha512"));
        assert_eq!(between(signature_input, "keyid=\"", "\";"), Some("123456789"));
        assert_eq!(between(signature_input, "created=", ";"), Some("1754065546"));
        assert_eq!(between(signature_input, "expires=", ";"), Some("1754066746"));
        assert_eq!(between(signature_input, "invalid=", ";"), None);
    }

    #[tokio::test]
    async fn test_signature_input_with_body() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746".to_string(),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:".to_string());
        headers.insert("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        headers.insert("created".to_string(), "1754065546".to_string());

        let parsed = SignatureInput::new(&headers, &derive_elements, requirements, true).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.created, Some(1754065546));
        assert_eq!(parsed.expires, Some(1754066746));
        assert_eq!(parsed.sig.len(), 5);

        let signature_params = parsed.get_signature_params();
        assert_eq!(
            signature_params.as_str(),
            "(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746"
        );

        let signature_base = parsed.get_signature_base();
        assert_eq!(
            signature_base,
            "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"content-type\": application/json
\"content-digest\": SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:
\"@method\": POST
\"@request-target\": /api/v1/resource
\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746"
        );
    }

    #[tokio::test]
    async fn test_signature_input_no_body() {
        let derive_elements = DeriveElements::new("POST", "/api/v1/resource", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("signature-input".to_string(), "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".to_string());
        headers.insert("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        headers.insert("created".to_string(), "1754065546".to_string());

        let parsed = SignatureInput::new(&headers, &derive_elements, requirements, false).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.created, Some(1754175188));
        assert_eq!(parsed.expires, Some(1754175488));
        assert_eq!(parsed.sig.len(), 3);

        let signature_params = parsed.get_signature_params();
        assert_eq!(signature_params.as_str(), "(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488");

        let signature_base = parsed.get_signature_base();
        assert_eq!(
            signature_base,
            "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"@method\": POST
\"@request-target\": /api/v1/resource
\"@signature-params\": (\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488"
        );
    }

    #[tokio::test]
    async fn test_verify_success_rsa_pss_sha512() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_config/keys/private_key1.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PSS_SHA512, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let public_key = fs::read("test_config/keys/public_key1.pem").unwrap();

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(Some(public_key), None));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_rsa_v1_5_sha256() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_config/keys/private_key2.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-v1_5-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PKCS1_SHA256, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-v1_5-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let public_key = fs::read("test_config/keys/public_key2.pem").unwrap();

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(Some(public_key), None));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p256_sha256() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &fs::read("test_config/keys/private_key5.pk8").unwrap(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": {}",
            "(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p256-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p256-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let public_key = fs::read("test_config/keys/public_key5.pem").unwrap();

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(Some(public_key), None));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p384_sha384() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &fs::read("test_config/keys/private_key6.pk8").unwrap(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": {}",
            "(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p384-sha384\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p384-sha384\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let public_key = fs::read("test_config/keys/public_key6.pem").unwrap();

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(Some(public_key), None));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ed25519() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&fs::read("test_config/keys/private_key4.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": {}",
            "(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ed25519\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );

        let signature = STANDARD.encode(key_pair.sign(signature_str.as_bytes()));

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ed25519\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(Some(fs::read("test_config/keys/public_key4.pem").unwrap()), None));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_hmac_sha256() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}\n\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"hmac-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793"
        );

        let signature = STANDARD.encode(ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"TestHMACKey"), signature_str.as_bytes()));

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"hmac-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let mut keys: HashMap<String, KeyParams> = HashMap::new();
        keys.insert("key123".to_string(), KeyParams::new(None, Some("TestHMACKey".to_string())));
        let service = HttpSignaturesService::new(requirements, keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_parse_signature_elements_success() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "", "", "", "", "");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        let parsed = SignatureInput::new(&headers, &derive_elements, requirements, false).unwrap();
        assert_eq!(parsed.sig.len(), 5);
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "date")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-type")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-digest")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Method { value: val } if val == "POST")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::RequestTarget { value: val } if val == "/foo?param=value&pet=dog")));
    }

    #[tokio::test]
    async fn test_parse_signature_elements_success_all_derived() {
        let derive_elements = DeriveElements::new("POST", "/foo?param=value&pet=dog", "/foo", "/foo", "example.com", "https", "?param=value&pet=dog");

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@target-uri\" \"@request-target\" \"@path\" \"@authority\" \"@scheme\" \"@query\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        let parsed = SignatureInput::new(&headers, &derive_elements, requirements, false).unwrap();
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "date")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-type")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-digest")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Method { value: val } if val == "POST")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::RequestTarget { value: val } if val == "/foo?param=value&pet=dog")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Path { value: val } if val == "/foo")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Authority { value: val } if val == "example.com")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Scheme { value: val } if val == "https")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Query { value: val } if val == "?param=value&pet=dog")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::TargetUri { value: val } if val == "/foo")));
    }

    #[tokio::test]
    async fn test_generate_signature_elements_rsa() {
        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_config/keys/private_key1.pk8").unwrap()).unwrap();
        let signature_base = "\"x-fd-userid\": 123456789
\"x-request-id\": 78867567565464
\"@method\": DELETE
\"@signature-params\": (\"x-fd-userid\" \"x-request-id\" \"@method\");alg=\"rsa-pss-sha512\";keyid=\"key1\";created=1755289691;expires=1955289991";
        let rand = SystemRandom::new();
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PSS_SHA512, &rand, signature_base.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);
        println!("Signature: \n{:?}", signature);
    }

    #[tokio::test]
    async fn test_generate_signature_elements_ed25519() {
        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&fs::read("test_config/keys/private_key4.pk8").unwrap()).unwrap();
        let signature_base = "\"x-fd-userid\": 123456789
\"x-request-id\": 78867567565464
\"@method\": POST
\"@signature-params\": (\"x-fd-userid\" \"x-request-id\" \"@method\");alg=\"ed25519\";keyid=\"key4\";created=1755289691;expires=1955289991";
        let sign = key_pair.sign(signature_base.as_bytes());
        let signature = STANDARD.encode(sign.as_ref());
        println!("Signature: \n{:?}", signature);
    }
}
