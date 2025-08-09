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
     * Whether the 'created' data is required.
     */
    created_required: bool,
    /**
     * Whether the 'expires' data is required.
     */
    expires_required: bool,
    /**
     * Whether to check if the signature has expired. Only relevant if `expires` is included in the signature.
     */
    check_expired: bool,
    /**
     * A set of headers that are required in the signature.
     */
    required_headers: HashSet<String>,
    /**
     * A set of headers that are required in the body signature. Example: `Content-Type`, `Content-Digest`, `Content-Length`.
     * If the body is signed, these headers must be included in the signature.
     */
    required_headers_body: HashSet<String>,
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
     * `created_required`: Whether the 'created' data is required.
     * `expires_required`: Whether the 'expires' data is required.
     * `check_expired`: Whether to check if the signature has expired.
     * `required_headers`: A set of headers that are required in the signature.
     * `required_headers_body`: A set of headers that are required in the body signature.
     * `keys`: A map of keys used for signature verification.
     *
     * # Returns
     * A new instance of `HttpSignaturesServicee`.  
     */
    pub fn new(created_required: bool, expires_required: bool, check_expired: bool, required_headers: HashSet<String>, required_headers_body: HashSet<String>, keys: HashMap<String, Vec<u8>>) -> Self {
        HttpSignaturesServicee { created_required, expires_required, check_expired, required_headers, required_headers_body, keys }
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
            &headers,
            &method,
            &target,
            self.created_required,
            self.expires_required,
            self.check_expired,
            self.required_headers.clone(),
            self.required_headers_body.clone(),
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
                    .verify(signature_base, &signature)
                    .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()))?;
                true
            }
            "rsa-v1_5-sha256" => {
                let public_key = ring::signature::UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pkey);
                public_key
                    .verify(signature_base, &signature)
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
            _ => return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Unsupported signature algorithm".to_string()).into()),
        };
        if result { Ok(()) } else { Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()).into()) }
    }
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
     * `created_required`: Whether the 'created' data is required.
     * `expires_required`: Whether the 'expires' data is required.
     * `check_expired`: Whether to check if the signature has expired.
     * `required_headers`: A set of headers that are required in the signature.
     * `required_headers_body`: A set of headers that are required in the body signature.
     * `has_body`: Whether the request has a body.
     * # Returns
     * A `SignatureInput` struct containing the parsed elements.
     */
    fn new(
        headers: &HeaderMap,
        method: &str,
        request_target: &str,
        created_required: bool,
        expires_required: bool,
        check_expired: bool,
        required_headers: HashSet<String>,
        required_headers_body: HashSet<String>,
        has_body: bool,
    ) -> Result<Self, ApplicationError> {
        let mut sig = Vec::new();
        let mut alg = String::new();
        let mut keyid = String::new();
        let mut created = None;
        let mut expires = None;

        let signature_input = headers
            .get("Signature-Input")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing Signature input header".to_string()))?;

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
        if created_required && created.is_none() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing created timestamp".to_string()));
        }
        if expires_required && expires.is_none() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing expires timestamp".to_string()));
        }
        if sig.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "No signature elements found".to_string()));
        }
        if has_body
            && (!required_headers_body.is_empty()
                && required_headers_body.iter().all(|header| !sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if *name == header.to_lowercase()))))
        {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, format!("Missing required body headers in signature body: {:?}", required_headers_body)));
        }
        if !required_headers.is_empty() {
            if required_headers.iter().all(|header| !sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if *name == header.to_lowercase()))) {
                return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, format!("Missing required headers in signature: {:?}", required_headers)));
            }
        }

        if check_expired {
            if let Some(expiry) = expires {
                if expiry < chrono::Utc::now().timestamp() as usize {
                    return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature has expired".to_string()));
                }
            }
        }
        if alg.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing algorithm in signature".to_string()));
        }
        if keyid.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing keyid in signature".to_string()));
        }
        for element in &sig {
            if let SignatureElementEnum::HeaderString { name, .. } = element {
                if !headers.contains_key(name) {
                    return Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, format!("Missing required header in signature: {}", name)));
                }
            }
        }
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
                signature_params.push_str(" ");
            } else {
                signature_params.push_str("(");
            }
            match element {
                SignatureElementEnum::HeaderString { name, value: _ } => {
                    signature_params.push_str(&format!("\"{}\"", name));
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
                signature_base.push_str("\n");
            }
            match element {
                SignatureElementEnum::HeaderString { name, value } => {
                    signature_base.push_str(&format!("\"{}\": {}", name, value));
                }
                SignatureElementEnum::Method { value } => {
                    signature_base.push_str(&format!("\"@method\": {}", value));
                }
                SignatureElementEnum::RequestTarget { value } => {
                    signature_base.push_str(&format!("\"@request-target\": {}", value));
                }
            }
        }
        println!("Signature Base: \n{}", signature_base);
        signature_base
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
    async fn test_signature_input() {
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("date", "Tue"),
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"date\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082")
                ]),
                "POST",
                "/api/v1/resource",
                false,
                false,
                false,
                HashSet::new(),
                HashSet::new(),
                false
            )
            .is_ok(),
            true
        );
        assert_eq!(
            SignatureInput::new(&into_headermap(vec![]), "POST", "/api/v1/resource", true, true, false, HashSet::new(), HashSet::new(), false).unwrap_err().message,
            "Missing Signature input header"
        );
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";expires=1754335082"
                )]),
                "POST",
                "/api/v1/resource",
                true,
                false,
                false,
                HashSet::new(),
                HashSet::new(),
                false
            )
            .unwrap_err()
            .message,
            "Missing created timestamp"
        );
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782"
                )]),
                "POST",
                "/api/v1/resource",
                false,
                true,
                false,
                HashSet::new(),
                HashSet::new(),
                false
            )
            .unwrap_err()
            .message,
            "Missing expires timestamp"
        );
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![(
                    "Signature-Input",
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0"
                )]),
                "POST",
                "/api/v1/resource",
                false,
                false,
                false,
                HashSet::from_iter(vec!["Accept".to_owned()]),
                HashSet::new(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required headers in signature: {\"Accept\"}"
        );
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("date", "Tue"),
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0")
                ]),
                "POST",
                "/api/v1/resource",
                false,
                false,
                false,
                HashSet::new(),
                HashSet::from_iter(vec!["Content-Length".to_owned()]),
                true
            )
            .unwrap_err()
            .message,
            "Missing required body headers in signature body: {\"Content-Length\"}"
        );
        assert_eq!(
            SignatureInput::new(
                &into_headermap(vec![
                    ("content-digest", "ghghgh"),
                    ("Signature-Input", "sig=(\"date\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=1754335082")
                ]),
                "POST",
                "/api/v1/resource",
                false,
                false,
                false,
                HashSet::new(),
                HashSet::new(),
                false
            )
            .unwrap_err()
            .message,
            "Missing required header in signature: date"
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

        let parsed = SignatureInput::new(&headers, method, request_target, false, false, false, HashSet::new(), HashSet::new(), true).unwrap();
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
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("date"), "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("created"), "1754065546".parse().unwrap());
        let method = "POST";
        let request_target = "/api/v1/resource";

        let parsed = SignatureInput::new(&headers, method, request_target, false, false, false, HashSet::new(), HashSet::new(), false).unwrap();
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
        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_keys/rsa_pss_private.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {}\n\"@request-target\": {}",
            method, request_target
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PSS_SHA512, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{}:", signature).parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(true, true, false, HashSet::new(), HashSet::new(), keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_rsa_v1_5_sha256() {
        let rand = SystemRandom::new();

        let key_pair = RsaKeyPair::from_pkcs8(&fs::read("test_keys/rsa_pss_private.pk8").unwrap()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {}\n\"@request-target\": {}",
            method, request_target
        );
        let mut signature_result = vec![0; key_pair.public().modulus_len()];
        key_pair.sign(&RSA_PKCS1_SHA256, &rand, signature_str.as_bytes(), &mut signature_result).unwrap();
        let signature = STANDARD.encode(&signature_result);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-v1_5-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{}:", signature).parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(true, true, false, HashSet::new(), HashSet::new(), keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p256_sha256() {
        let rand = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rand).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {}\n\"@request-target\": {}",
            method, request_target
        );
        println!("{}", signature_str);
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p256-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{}:", signature).parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(true, true, false, HashSet::new(), HashSet::new(), keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ecdsa_p384_sha384() {
        let rand = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rand).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rand).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {}\n\"@request-target\": {}",
            method, request_target
        );
        println!("{}", signature_str);
        let signature = STANDARD.encode(key_pair.sign(&rand, signature_str.as_bytes()).unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ecdsa-p384-sha384\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{}:", signature).parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(true, true, false, HashSet::new(), HashSet::new(), keys);
        let result = service.verify_signature(&headers, method, request_target);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_success_ed25519() {
        let rand = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rand).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let signature_str = format!(
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@method\": {}\n\"@request-target\": {}",
            method, request_target
        );
        println!("{}", signature_str);
        let signature = STANDARD.encode(key_pair.sign(signature_str.as_bytes()));

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("signature-input"),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"ed25519\";keyid=\"key123\";created=1754409493;expires=1754409793".parse().unwrap(),
        );
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{}:", signature).parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());

        let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
        keys.insert("key123".to_string(), key_pair.public_key().as_ref().to_vec());
        let service = HttpSignaturesServicee::new(true, true, false, HashSet::new(), HashSet::new(), keys);
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
