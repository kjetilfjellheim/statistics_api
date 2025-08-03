use std::{collections::{HashMap, HashSet}};

use actix_web::http::header::HeaderMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{hash::MessageDigest};

use crate::model::apperror::ApplicationError;

/**
 * Service for handling HTTP signatures.
 */
pub struct HttpSignaturesServicee {
    header_defs: HashMap<String, HeaderType>,
    created_required: bool,
    expires_required: bool,
    required_headers: HashSet<String>,
    required_headers_body: HashSet<String>,
    keys: HashMap<String, openssl::pkey::PKey<openssl::pkey::Public>>,
}

impl HttpSignaturesServicee {

    /**
     * Creates a new instance of `HttpSignaturesServicee`.
     * 
     * # Arguments
     * `header_defs`: A map defining the headers and their types.
     * `created_required`: Whether the 'created' header is required.
     * `expires_required`: Whether the 'expires' header is required.
     * `required_headers`: A set of headers that are required in the signature.
     * `required_headers_body`: A set of headers that are required in the body signature.
     * `keys`: A map of keys used for signature verification.
     * 
     * # Returns
     * A new instance of `HttpSignaturesServicee`.  
     */
    pub fn new(
        header_defs: HashMap<String, HeaderType>,
        created_required: bool,
        expires_required: bool,
        required_headers: HashSet<String>,
        required_headers_body: HashSet<String>,
        keys: HashMap<String, openssl::pkey::PKey<openssl::pkey::Public>>,
    ) -> Self {
        HttpSignaturesServicee {
            header_defs,
            created_required,
            expires_required,
            required_headers,
            required_headers_body,
            keys,
        }
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
    fn verify_signature(&self,
        headers: &HeaderMap,
        method: &str,
        target: &str,
    ) -> Result<(), ApplicationError> {
        let signature = Self::get_signature(headers.get("Signature").and_then(|s| s.to_str().ok()).ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Missing Signature header".to_string()))?)?;
        let signature = STANDARD.decode(signature.as_bytes())
            .map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Invalid signature format".to_string()))?;
        let signature_input = SignatureInput::new(
            &self.header_defs,
            &headers,
            &method,
            &target,
            self.created_required,
            self.expires_required,
            self.required_headers.clone(),
            self.required_headers_body.clone(),
            headers.contains_key("Content-Digest") || headers.contains_key("Content-Type") || headers.contains_key("Content-Length"),
        )?;
        let pkey = self.keys.get(&signature_input.keyid)
            .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Key not found".to_string()))?;
        let mut verifier = openssl::sign::Verifier::new( MessageDigest::sha512(), pkey).unwrap();
        let result = verifier.verify_oneshot(&signature, &signature_input.get_signature_base().as_bytes()).unwrap();
        if result {
            Ok(())
        } else {
            Err(ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Signature verification failed".to_string()).into())
        }
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
        between(signature, "sig=:", ":").map(|s| s.to_string())
            .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::SignatureVerification, "Invalid signature format".to_string()))
    }

}

/**
 * Represents the type of a header in the HTTP signature.
 */
#[derive(Debug, Clone)]
pub enum HeaderType {
    String,
    Value,
}


#[derive(Debug)]
enum SignatureElementEnum {
    HeaderValue { name: String, value: usize },
    HeaderString { name: String, value: String },
    Method { value: String },
    RequestTarget { value: String },
}

#[derive(Debug)]
struct SignatureInput {
    sig: Vec<SignatureElementEnum>,
    alg: String,
    keyid: String,
    created: Option<usize>,
    expires: Option<usize>,
}

impl SignatureInput {
    /**
     * Parses a signature input string into a `SignatureInput` struct.
     * 
     * # Arguments
     * `signature_input`: The signature input string to parse.
     * `header_defs`: A map of header definitions to determine the type the headers contains.
     * 
     * # Returns
     * A `SignatureInput` struct containing the parsed elements.
     */
    fn new(header_defs: &HashMap<String, HeaderType>, headers: &HeaderMap, method: &str, request_target: &str, created_required: bool, expires_required: bool, required_headers: HashSet<String>, required_headers_body: HashSet<String>, has_body: bool) -> Result<Self, ApplicationError> {
        let mut sig = Vec::new();
        let mut alg = String::new();
        let mut keyid = String::new();
        let mut created = None;
        let mut expires = None;

        let signature_input = headers.get("Signature-Input").and_then(|h| h.to_str().ok()).ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::Application, "Missing Signature header".to_string()))?;

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
                        if let Some(header_type) = header_defs.get(element) {
                            match header_type {
                                HeaderType::String => {
                                    sig.push(SignatureElementEnum::HeaderString { name: element.to_string().to_lowercase(), value: headers.get(element).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string() });
                                },
                                HeaderType::Value => {
                                    sig.push(SignatureElementEnum::HeaderValue { name: element.to_string().to_lowercase(), value: headers.get(element).and_then(|f| f.to_str().ok()).unwrap_or_default().parse().unwrap_or_default() });
                                },
                            }
                        } else {
                            sig.push(SignatureElementEnum::HeaderString { name: element.to_string().to_lowercase(), value:headers.get(element).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string() });
                        }
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
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, "Missing created timestamp".to_string()));
        }
        if expires_required && expires.is_none() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, "Missing expires timestamp".to_string()));
        }
        if sig.is_empty() {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, "No signature elements found".to_string()));
        }
        if has_body && (!required_headers_body.is_empty() && required_headers_body.iter().all(|header| !sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if *name == header.to_lowercase())))) {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, format!("Missing required body headers in signature body: {:?}", required_headers_body)));
        }
        if required_headers.iter().any(|header| !sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if *name == header.to_lowercase()))) {
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, format!("Missing required headers in signature: {:?}", required_headers)));
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
                SignatureElementEnum::HeaderValue { name, value: _ } => {
                    signature_params.push_str(&format!("\"{}\"", name));
                },
                SignatureElementEnum::HeaderString { name, value: _ } => {
                    signature_params.push_str(&format!("\"{}\"", name));
                },
                SignatureElementEnum::Method { value: _ } => {
                    signature_params.push_str("\"@method\"");
                },
                SignatureElementEnum::RequestTarget { value: _ } => {
                    signature_params.push_str("\"@request-target\"");
                },
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

    fn get_signature_base(&self) -> String {
        let mut signature_base = String::new();
        for element in &self.sig {
            if !signature_base.is_empty() {
                signature_base.push_str("\n");
            }
            match element {
                SignatureElementEnum::HeaderValue { name, value } => {
                    signature_base.push_str(&format!("\"{}\": {}", name, value));
                },
                SignatureElementEnum::HeaderString { name, value } => {
                    signature_base.push_str(&format!("\"{}\": {}", name, value));
                },
                SignatureElementEnum::Method { value } => {
                    signature_base.push_str(&format!("\"@method\": {}", value));
                },
                SignatureElementEnum::RequestTarget { value } => {
                    signature_base.push_str(&format!("\"@request-target\": {}", value));
                },
            }
        }
        println!("{}", signature_base);
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
    use std::{collections::{HashMap, HashSet}, fs};

    use actix_web::http::header::{HeaderMap, HeaderName};

    use super::*;

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
        let mut header_defs = HashMap::new();
        header_defs.insert("content-type".to_string(), HeaderType::String);
        header_defs.insert("content-digest".to_string(), HeaderType::String);
        header_defs.insert("created".to_string(), HeaderType::Value);
        header_defs.insert("expires".to_string(), HeaderType::Value);
        header_defs.insert("date".to_string(), HeaderType::String);

        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("signature-input"), "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746".parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("created"), "1754065546".parse().unwrap());
        let method = "POST";
        let request_target = "/api/v1/resource";

        let parsed = SignatureInput::new(&header_defs, &headers, method, request_target, false, false, HashSet::new(), HashSet::new(), true).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.created, Some(1754065546));
        assert_eq!(parsed.expires, Some(1754066746));
        assert_eq!(parsed.sig.len(), 5);

        let signature_params = parsed.get_signature_params();
        assert_eq!(signature_params.as_str(), "(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746");

        let signature_base = parsed.get_signature_base();
        assert_eq!(signature_base, "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"content-type\": application/json
\"content-digest\": SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:
\"@method\": POST
\"@request-target\": /api/v1/resource");
    }

    #[tokio::test]
    async fn test_signature_input_no_body() {
        let mut header_defs = HashMap::new();
        header_defs.insert("content-type".to_string(), HeaderType::String);
        header_defs.insert("content-digest".to_string(), HeaderType::String);
        header_defs.insert("created".to_string(), HeaderType::Value);
        header_defs.insert("expires".to_string(), HeaderType::Value);
        header_defs.insert("date".to_string(), HeaderType::String);

        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("signature-input"), "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Mon, 01 Jan 2024 00:00:00 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("created"), "1754065546".parse().unwrap());
        let method = "POST";
        let request_target = "/api/v1/resource";

        let parsed = SignatureInput::new(&header_defs, &headers, method, request_target, false, false, HashSet::new(), HashSet::new(), false).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.created, Some(1754175188));
        assert_eq!(parsed.expires, Some(1754175488));
        assert_eq!(parsed.sig.len(), 3);

        let signature_params = parsed.get_signature_params();
        assert_eq!(signature_params.as_str(), "(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488");

        let signature_base = parsed.get_signature_base();
        assert_eq!(signature_base, "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"@method\": POST
\"@request-target\": /api/v1/resource");

    }

    #[tokio::test]
    async fn test_verify_success() {
        let data_to_sign = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
\"content-type\": application/json\n\
\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\
\"@method\": POST\n\
\"@request-target\": /foo?param=value&pet=dog".to_string();
        let pem_sign = fs::read("/home/kjetil/test_certs/rsa_private.key").unwrap();
        let private_key = openssl::rsa::Rsa::private_key_from_pem(&pem_sign).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(private_key).unwrap();
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), &pkey).unwrap();
        signer.update(data_to_sign.as_bytes()).unwrap();
        let signature = signer.sign_to_vec().unwrap();
        let signature = STANDARD.encode(&signature);


        let header_defs = HashMap::new();

        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static("signature-input"), "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754257581;expires=19754257881".parse().unwrap());
        headers.insert(HeaderName::from_static("content-type"), "application/json".parse().unwrap());
        headers.insert(HeaderName::from_static("content-digest"), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".parse().unwrap());
        headers.insert(HeaderName::from_static("date"), "Tue, 20 Apr 2021 02:07:55 GMT".parse().unwrap());
        headers.insert(HeaderName::from_static("signature"), format!("sig=:{signature}:").parse().unwrap());

        let method = "POST";
        let request_target = "/foo?param=value&pet=dog";

        let mut keys = HashMap::new();
        let pem_data = fs::read("/home/kjetil/test_certs/public_key.pem").unwrap();
        let public_key = openssl::rsa::Rsa::public_key_from_pem(&pem_data).unwrap();
        let pkey = openssl::pkey::PKey::from_rsa(public_key).unwrap();
        keys.insert("key123".to_string(), pkey);
        let service = HttpSignaturesServicee::new(header_defs, true, true, HashSet::new(), HashSet::new(), keys);
        assert!(service.verify_signature(&headers, method, request_target).is_ok());
    } 

}
