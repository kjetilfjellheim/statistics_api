use std::collections::{HashMap, HashSet};

use actix_web::http::header::HeaderMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PSS_2048_8192_SHA512};

use crate::model::apperror::ApplicationError;

/**
 * Service for handling HTTP signatures.
 */
pub struct HttpSignaturesServicee {
    /**
     * A set of requirements for signature verification.
     */
    requirements: HashSet<VerificationRequirement>,
    /**
     * A map of keys used for signature verification. The key ID is used to look up the public key.
     * The key ID is expected to be in the `keyid` field of the signature input.
     */
    keys: HashMap<String, Vec<u8>>,
}

impl HttpSignaturesServicee {
    /**
     * Creates a new instance of `HttpSignaturesServicee`.
     *
     * # Arguments
     * `requirements`: A set of requirements for signature verification.
     * `keys`: A map of keys used for signature verification.
     *
     * # Returns
     * A new instance of `HttpSignaturesServicee`.  
     */
    pub fn new(requirements: HashSet<VerificationRequirement>, keys: HashMap<String, Vec<u8>>) -> Self {
        HttpSignaturesServicee { requirements, keys }
    }

    /**
     * Verifies the HTTP signature of a request.
     *
     * # Arguments
     * `headers`: The headers of the request.
     * `method`: The HTTP method of the request.
     * `target`: The request target (URL).
     *
     * # Returns
     * A `Result` indicating success or failure of the verification.
     */
    fn verify_signature(&self, headers: &HeaderMap, method: &str, target: &str) -> Result<(), ApplicationError> {
        let signature = Self::get_signature(
            headers
                .get("Signature")
                .and_then(|s| s.to_str().ok())
                .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing Signature header".to_string()))?,
        )?;
        let signature = STANDARD.decode(signature.as_bytes()).map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Invalid signature format".to_string()))?;
        let signature_input = SignatureInput::new(
            headers,
            method,
            target,
            self.requirements.clone(),
            headers.contains_key("Content-Digest") || headers.contains_key("Content-Type") || headers.contains_key("Content-Length"),
        )?;
        let pkey = self.keys.get(&signature_input.keyid).ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Key not found".to_string()))?;
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
    fn get_signature(signature: &str) -> Result<String, ApplicationError> {
        between(signature, "sig=:", ":").map(|s| s.to_string()).ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Invalid signature format".to_string()))
    }

    /**
     * Verifies the signature using the provided algorithm and public key.
     *
     * # Arguments
     * `algorithm`: The signature algorithm used (e.g., "RSA-PSS-SHA256").
     * `pkey`: The public key used for verification.
     * `signature_base`: The base string to verify against the signature.
     * `signature`: The signature to verify.
     *
     * # Returns
     * A `Result` indicating success or failure of the verification.
     */
    fn verify(algorithm: &str, pkey: &Vec<u8>, signature_base: &[u8], signature: &[u8]) -> Result<(), ApplicationError> {
        let result = match algorithm.to_lowercase().as_str() {
            "rsa-pss-sha512" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, &pkey);
                public_key
                    .verify(signature_base, signature)
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            "rsa-v1_5-sha256" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
                public_key
                    .verify(signature_base, signature)
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            "hmac-sha256" => {
                return Err(ApplicationError::new(
                    crate::model::apperror::ErrorType::SignatureVerification,
                    "hmac-sha256 is not supported in this implementation, please use hmac-sha512 instead".to_string(),
                ));
            }
            "ecdsa-p256-sha256" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pkey);
                public_key
                    .verify(signature_base, signature)
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            "ecdsa-p384-sha384" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, &pkey);
                public_key
                    .verify(signature_base, signature)
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            "ed25519" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&ED25519, &pkey);
                public_key
                    .verify(signature_base.as_ref(), signature.as_ref())
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            _ => return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Unsupported signature algorithm".to_string())),
        };
        if result { Ok(()) } else { Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string())) }
    }
}

/**
 * Represents the requirements for verifying a signature.
 */
#[derive(Clone)]
pub enum VerificationRequirement {
    /**
     * Represents a header that is required in the signature. 
     */
    HeaderRequired{ name: String },
    /**
     * Represents a header that is required in the signature if the body is present.
     */
    HeaderRequiredIfBodyPresent{ name: String },
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
    DerivedRequired{ name: String },
}

impl std::hash::Hash for VerificationRequirement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            VerificationRequirement::HeaderRequired { name } => {
                state.write_u8(0);
                name.to_lowercase().hash(state);
            }
            VerificationRequirement::HeaderRequiredIfBodyPresent { name } => {
                state.write_u8(1);
                name.to_lowercase().hash(state);
            }
            VerificationRequirement::CreatedRequired => state.write_u8(2),
            VerificationRequirement::ExpiresRequired => state.write_u8(3),
            VerificationRequirement::CheckExpired => state.write_u8(4),
            VerificationRequirement::DerivedRequired { name } => {
                state.write_u8(5);
                name.to_lowercase().hash(state);
            }
        }
    }
}

impl PartialEq for VerificationRequirement {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::HeaderRequired { name: l_name }, Self::HeaderRequired { name: r_name }) => l_name.to_lowercase() == r_name.to_lowercase(),
            (Self::HeaderRequiredIfBodyPresent { name: l_name }, Self::HeaderRequiredIfBodyPresent { name: r_name }) => l_name.to_lowercase() == r_name.to_lowercase(),
            (Self::DerivedRequired { name: l_name }, Self::DerivedRequired { name: r_name }) => l_name.to_lowercase() == r_name.to_lowercase(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl std::cmp::Eq for VerificationRequirement {

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
     * # Arguments
     * `headers`: Header map containing the signature input.
     * `method`: The HTTP method of the request.
     * `request_target`: The request target (URL).
     * `requirements`: Verification requirements.
     * `has_body`: Whether the request has a body.
     * # Returns
     * A `SignatureInput` struct containing the parsed elements.
     */
    fn new(
        headers: &HeaderMap,
        method: &str,
        request_target: &str,
        requirements: HashSet<VerificationRequirement>,
        has_body: bool,
    ) -> Result<Self, ApplicationError> {
        let signature_input = headers
            .get("Signature-Input")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing Signature input header".to_string()))?;

        let (sig, alg, keyid, created, expires) = Self::get_signature_elements(headers, method, request_target, signature_input);
        Self::verify_created_requirement(&requirements, created)?;
        Self::verify_expires_requirement(&requirements, expires)?;
        Self::verify_empty_signature_elements(&sig)?;
        Self::verify_body_headers(&requirements, has_body, &sig)?;
        Self::verify_headers(&requirements, &sig)?;
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
            }
        }
        signature_base
    }

    /**
     * Get the signature elements from the signature input string.
     *
     * #Arguments
     * `headers`: The headers of the request.
     * `method`: The HTTP method of the request.
     * `request_target`: The request target (URL).
     * `signature_input`: The signature input string.
     *
     * # Returns
     * A tuple containing the updated signature elements, algorithm, key ID, created timestamp, and expires timestamp.
     */
    fn get_signature_elements(headers: &HeaderMap, method: &str, request_target: &str, signature_input: &str) -> (Vec<SignatureElementEnum>, String, String, Option<usize>, Option<usize>) {
        let mut sig = Vec::new();
        let mut alg = String::new();
        let mut keyid = String::new();
        let mut created: Option<usize> = None;
        let mut expires: Option<usize> = None;
        for part in signature_input.split(';') {
            if part.starts_with("sig=(") {
                let value = between(part, "sig=(", ")").unwrap_or_default();
                for element in value.replace("\"", "").split_whitespace() {
                    if element.starts_with('@') {
                        if element == "@method" {
                            sig.push(SignatureElementEnum::Method { value: method.to_string() });
                        } else if element == "@request-target" {
                            sig.push(SignatureElementEnum::RequestTarget { value: request_target.to_string() });
                        }
                    } else {
                        sig.push(SignatureElementEnum::HeaderString {
                            name: element.to_string().to_lowercase(),
                            value: headers.get(element).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string(),
                        });
                    }
                }
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
     * Verifies the created requirement for the signature input.
     *
     * # Arguments
     * `requirements`: The set of verification requirements.
     * `created`: The created timestamp from the signature input.
     *
     * # Returns
     * Ok if the created requirement is satisfied, otherwise an `ApplicationError`.
     */
    fn verify_created_requirement(requirements: &HashSet<VerificationRequirement>, created: Option<usize>) -> Result<(), ApplicationError> {
        if requirements.contains(&VerificationRequirement::CreatedRequired) && created.is_none() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing created timestamp".to_string()));
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
     * Ok if the expires requirement is satisfied, otherwise an `ApplicationError`.
     */
    fn verify_expires_requirement(requirements: &HashSet<VerificationRequirement>, expires: Option<usize>) -> Result<(), ApplicationError> {
        if requirements.contains(&VerificationRequirement::ExpiresRequired) && expires.is_none() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing expires timestamp".to_string()));
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
     * Ok if the signature elements are not empty, otherwise an `ApplicationError`.
     */
    fn verify_empty_signature_elements(sig: &[SignatureElementEnum]) -> Result<(), ApplicationError> {
        if sig.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "No signature elements found".to_string()));
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
     * Ok if the body headers are verified, otherwise an `ApplicationError`.
     */
    fn verify_body_headers(requirements: &HashSet<VerificationRequirement>, has_body: bool, sig: &[SignatureElementEnum]) -> Result<(), ApplicationError> {
        if has_body {
            let body_reqs = requirements.iter().all(|f| {
                match f {
                    VerificationRequirement::HeaderRequiredIfBodyPresent { name } => {
                        sig.iter().any(|f| {
                            matches!(f, SignatureElementEnum::HeaderString { name: n, .. } if n == name)
                        })
                    },
                    _ => true
                }
            });
            if !body_reqs {
                return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing required body headers in signature".to_string()));
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
     * Ok if all required headers are present, otherwise an `ApplicationError`.
     */
    fn verify_headers(requirements: &HashSet<VerificationRequirement>, sig: &[SignatureElementEnum]) -> Result<(), ApplicationError> {
        let header_reqs = requirements.iter().all(|f| {
            match f {
                VerificationRequirement::HeaderRequired { name } => {
                    sig.iter().any(|f| {
                        matches!(f, SignatureElementEnum::HeaderString { name: n, .. } if n == name)
                    })
                },
                _ => true
            }
        });
        if !header_reqs {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing required header in signature".to_string()));
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
     * Ok if all required derived values are present, otherwise an `ApplicationError`.
     */
    fn verify_derived(requirements: &HashSet<VerificationRequirement>, sig: &[SignatureElementEnum]) -> Result<(), ApplicationError> {
        let derived_reqs = requirements.iter().all(|f| {
            match f {
                VerificationRequirement::DerivedRequired { name } => {
                    let mut derived: bool = false;
                    if name == "@method" {
                        derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Method { .. }));
                    }
                    if name == "@request-target" {
                        derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::RequestTarget { .. }));
                    }
                    derived
                },
                _ => true
            }
        });
        if !derived_reqs {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing required derived value in signature".to_string()));
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
     * An `Ok(())` if the signature is valid, or an `ApplicationError` if it is not.
     */
    fn check_expired(requirements: HashSet<VerificationRequirement>, expires: Option<usize>) -> Result<(), ApplicationError> {
        if requirements.contains(&VerificationRequirement::CheckExpired) {
            if let Some(expiry) = expires {
                if expiry < chrono::Utc::now().timestamp() as usize {
                    return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature has expired".to_string()));
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
     * An `Ok(())` if the algorithm is valid, or an `ApplicationError` if it is not.
     */
    fn verify_algorithm(alg: &str) -> Result<(), ApplicationError> {
        if alg.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing algorithm in signature".to_string()));
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
    * An `Ok(())` if the key ID is valid, or an `ApplicationError` if it is not.
    */
    fn verify_keyid(keyid: &str) -> Result<(), ApplicationError> {
        if keyid.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing keyid in signature".to_string()));
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
     * Ok if all required headers are present, otherwise an `ApplicationError`.
     */
    fn verify_request_headers(headers: &HeaderMap, sig: &Vec<SignatureElementEnum>) -> Result<(), ApplicationError> {
        for element in sig {
            if let SignatureElementEnum::HeaderString { name, .. } = element {
                if !headers.contains_key(name) {
                    return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, format!("Required header is missing from request: {name}")));
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

#[cfg(test)]
mod test {
    use std::{
        collections::{HashMap, HashSet},
        fs,
    };

    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA512, RsaKeyPair},
    };

    use super::*;

    #[tokio::test]
    async fn test_missing_signature() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();
        assert!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("date", "Tue"),
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"date\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .is_ok()
        );
        assert_eq!(
            SignatureInput::new(&into_headermap(vec![]), "POST", "/api/v1/resource", requirements.clone(), false).unwrap_err().message,
            "Missing Signature input header"
        );
    }

    #[tokio::test]
    async fn test_missing_created() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::CreatedRequired);
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";expires=1754335082"
                )]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing created timestamp"
        );
    }

    #[tokio::test]
    async fn test_missing_expires() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::ExpiresRequired);
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782"
                )]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing expires timestamp"
        );
    }

    #[tokio::test]
    async fn test_missing_accept() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "accept".into() });
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0"
                )]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required header in signature"
        );
    }

    #[tokio::test]
    async fn test_missing_required_body_content_length() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-length".into() });
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("date", "Tue"),
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                true
            )
            .unwrap_err()
            .message,
            "Missing required body headers in signature"
        );
    }

    #[tokio::test]
    async fn test_missing_required_header_date() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "date".into() });
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required header in signature"
        );
    }

    #[tokio::test]
    async fn test_missing_derived() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@method".into() });
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@request-target".into() });
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"content-digest\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required derived value in signature"
        );
    }

    #[tokio::test]
    async fn test_check_expired() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::CheckExpired);
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1554335082")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Signature has expired"
        );
    }

    #[tokio::test]
    async fn test_full_test() {
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "date".into() });
        requirements.insert(VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".into() });
        requirements.insert(VerificationRequirement::ExpiresRequired);
        requirements.insert(VerificationRequirement::CreatedRequired);
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@method".into() });
        requirements.insert(VerificationRequirement::DerivedRequired { name: "@request-target".into() });
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1954335082")
                ]),
                "POST",
                "/api/v1/resource",
                requirements.clone(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required header in signature"
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
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("created"), "1754065546".parse().unwrap());
        let method = "POST";
        let request_target = "/api/v1/resource";

        let parsed = SignatureInput::new(&headers, method, request_target, requirements, true).unwrap();
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
\"@request-target\": /api/v1/resource"
        );
    }

    #[tokio::test]
    async fn test_signature_input_no_body() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("date"), "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("created"), "1754065546".parse().unwrap());
        let method = "POST";
        let request_target = "/api/v1/resource";

        let parsed = SignatureInput::new(&headers, method, request_target, requirements, false).unwrap();
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
\"@request-target\": /api/v1/resource"
        );
    }

    #[tokio::test]
    async fn test_verify_success_rsa_pss_sha512() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_keys/rsa_pss_private.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}"
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PSS_SHA512, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(requirements, keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_rsa_v1_5_sha256() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_keys/rsa_pss_private.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}"
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PKCS1_SHA256, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-v1_5-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(requirements, keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p256_sha256() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}"
        );
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p256-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(requirements, keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p384_sha384() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rand).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}"
        );
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p384-sha384\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(requirements, keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ed25519() {
        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let rand = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rand).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {method}\n\"@request-target\": {request_target}"
        );

        let signature = STANDARD.encode(key_pair.sign(signature_str.as_bytes()));

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ed25519\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(requirements, keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    fn into_headermap(headers: Vec<(&'static str, &'static str)>) -> HeaderMap {
        let mut header_map = HeaderMap::new();
        for (name, value) in headers {
            let name_lower: String = name.to_owned().to_lowercase();
            header_map.insert(HeaderName::try_from(name_lower.as_str()).unwrap(), HeaderValue::from_static(value));
        }
        header_map
    }
}
