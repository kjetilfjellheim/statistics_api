use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    str::FromStr,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, warn};

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
     * Secret key used for generating signatures.
     */
    generating_secret: Option<SecurityKeyEnum>,
    /**
     * Response signature generation requirements.
     */
    response_generation_requirements: Option<HashSet<GenerationRequirement>>,
    /**
     * A set of requirements for input signature verification. If none then all signatures are accepted.
     */
    input_verification_requirements: Option<HashSet<VerificationRequirement>>,
    /**
     * A map of keys used for signature verification. The key ID is used to look up the public key.
     * The key ID is expected to be in the `keyid` field of the signature input.
     */
    verification_secrets: HashMap<String, SecurityKeyEnum>,
}

impl HttpSignaturesService {
    /**
     * Creates a new instance of `HttpSignaturesService`.
     *
     * # Arguments
     * `response_generation_requirements`: A set of requirements for response signature generation.
     * `input_verification_requirements`: A set of requirements for signature verification.
     * `input_keys`: A map of keys used for signature verification.
     *
     * # Returns
     * A new instance of `HttpSignaturesService`.  
     */
    pub fn new(
        generating_secret: Option<SecurityKeyEnum>,
        response_generation_requirements: Option<HashSet<GenerationRequirement>>,
        input_verification_requirements: Option<HashSet<VerificationRequirement>>,
        verification_secrets: HashMap<String, SecurityKeyEnum>,
    ) -> Self {
        HttpSignaturesService { generating_secret, response_generation_requirements, input_verification_requirements, verification_secrets }
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
    pub fn verify_signature(&self, headers: &HashMap<String, String>, derive_elements: &DeriveInputElements) -> Result<(), HttpSignaturesError> {
        if let Some(requirements) = &self.input_verification_requirements {
            debug!("Verifying signature with headers: {:?}", headers);
            let signature = Self::get_signature(headers.get("signature").ok_or(HttpSignaturesError::MissingSignatureHeader)?)?;
            let signature = STANDARD.decode(signature.as_bytes()).map_err(|_| HttpSignaturesError::InvalidSignatureFormat)?;
            let signature_input =
                SignatureInput::new(headers, derive_elements, requirements, headers.contains_key("content-digest") || headers.contains_key("content-type") || headers.contains_key("content-length"))?;
            let security_key = self.verification_secrets.get(&signature_input.keyid).ok_or(HttpSignaturesError::KeyNotFound { keyid: signature_input.keyid.clone() })?;
            Self::verify(signature_input.alg.as_str(), security_key, signature_input.get_signature_base().as_bytes(), &signature)?;
            debug!("Signature verified successfully");
        }
        Ok(())
    }

    /**
     * Generates a response signature for the given headers and derived elements.
     *
     * # Arguments
     * `headers`: The headers of the request.
     * `derive_elements`: The derived elements for signature generation.
     *
     * # Returns
     * A `Result` containing the generated signature or an error if generation fails.
     */
    pub fn generate_response_signature(&self, headers: &HashMap<String, String>, derive_elements: &DeriveInputElements) -> Result<Option<(String, String)>, HttpSignaturesError> {
        if let Some(requirements) = &self.response_generation_requirements
            && let Some(generating_secret) = &self.generating_secret
        {
            debug!("Generating signature with headers: {:?}", headers);

            let signature_output = SignatureOutput::new(
                headers,
                derive_elements,
                requirements,
                generating_secret.get_key_id(),
                &generating_secret.get_algorithm_string(),
                headers.contains_key("content-digest") || headers.contains_key("content-type") || headers.contains_key("content-length"),
            );
            let security_key = self.generating_secret.as_ref().ok_or(HttpSignaturesError::MissingGeneratingSecret)?;
            let signature = Self::sign(signature_output.alg.as_str(), security_key, signature_output.get_signature_base().as_bytes())?;
            debug!("Signature generated successfully");
            if let Some(signature) = signature {
                return Ok(Some((signature, format!("sig={}", signature_output.get_signature_params()))));
            }
        }
        Ok(None)
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
     * `security_key`: The key parameters for verification.
     * `signature_base`: The base string to verify against the signature.
     * `signature`: The signature to verify.
     *
     * # Returns
     * A `Result` indicating success or failure of the verification.
     */
    fn verify(algorithm: &str, security_key: &SecurityKeyEnum, signature_base: &[u8], signature: &[u8]) -> Result<(), HttpSignaturesError> {
        if algorithm != security_key.get_algorithm_string() {
            return Err(HttpSignaturesError::InvalidSignatureFormat);
        }
        security_key.verify_signature(signature, signature_base)?;
        Ok(())
    }

    /**
     * Signs the signature base using the provided algorithm and private key.
     *
     * # Arguments
     * `algorithm`: The signature algorithm used (e.g., "RSA-PSS-SHA256").
     * `security_key`: The key parameters for signing.
     * `signature_base`: The base string to sign.
     *
     * # Returns
     * A `Result` containing the generated signature or an error if signing fails.
     */
    fn sign(algorithm: &str, security_key: &SecurityKeyEnum, signature_base: &[u8]) -> Result<Option<String>, HttpSignaturesError> {
        if algorithm != security_key.get_algorithm_string() {
            return Err(HttpSignaturesError::InvalidSignatureFormat);
        }
        let signature = security_key.generate_signature(signature_base)?;
        Ok(Some(format!("sig=:{}:", STANDARD.encode(signature))))
    }
}

/**
 * Represents the algorithm used for signing.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    /**
     * RSA PSS with SHA-512.
     */
    RsaPssSha512,
    /**
     * RSA PKCS1 with SHA-256.
     */
    RsaPkcs1Sha256,
    /**
     * ECDSA P256 with SHA-256.
     */
    EcdsaP256Sha256,
    /**
     * ECDSA P384 with SHA-384.
     */
    EcdsaP384Sha384,
    /**
     * Ed25519.
     */
    Ed25519,
    /**
     * HMAC with SHA-256.
     */
    HmacSha256,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::RsaPssSha512 => write!(f, "{SIGNATURE_ALGORITHM_RSA_PSS_SHA512}"),
            Algorithm::RsaPkcs1Sha256 => write!(f, "{SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256}"),
            Algorithm::EcdsaP256Sha256 => write!(f, "{SIGNATURE_ALGORITHM_ECDSA_P256_SHA256}"),
            Algorithm::EcdsaP384Sha384 => write!(f, "{SIGNATURE_ALGORITHM_ECDSA_P384_SHA384}"),
            Algorithm::Ed25519 => write!(f, "{SIGNATURE_ALGORITHM_ED25519}"),
            Algorithm::HmacSha256 => write!(f, "{SIGNATURE_ALGORITHM_HMAC_SHA256}"),
        }
    }
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            SIGNATURE_ALGORITHM_RSA_PSS_SHA512 => Ok(Algorithm::RsaPssSha512),
            SIGNATURE_ALGORITHM_RSA_PKCS1_SHA256 => Ok(Algorithm::RsaPkcs1Sha256),
            SIGNATURE_ALGORITHM_ECDSA_P256_SHA256 => Ok(Algorithm::EcdsaP256Sha256),
            SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 => Ok(Algorithm::EcdsaP384Sha384),
            SIGNATURE_ALGORITHM_ED25519 => Ok(Algorithm::Ed25519),
            SIGNATURE_ALGORITHM_HMAC_SHA256 => Ok(Algorithm::HmacSha256),
            _ => Err(()),
        }
    }
}

/**
 * Derived elements for HTTP signatures. These elements are used to derive the signature base string.
 * They are typically derived from the HTTP request or response.
 */
#[derive(Debug, Clone)]
pub struct DeriveInputElements {
    /**
     * The method derived element.
     */
    pub method: Option<String>,
    /**
     * The request target derived element.
     */
    pub request_target: Option<String>,
    /**
     * The path derived element.
     */
    pub path: Option<String>,
    /**
     * The target URI derived element.
     */
    pub target_uri: Option<String>,
    /**
     * The authority derived element.
     */
    pub authority: Option<String>,
    /**
     * The scheme derived element.
     */
    pub scheme: Option<String>,
    /**
     * The query derived element.
     */
    pub query: Option<String>,
    /**
     * The status of the response.
     */
    pub status: Option<u16>,
}

impl DeriveInputElements {
    /**
     * Creates a new instance of `DeriveInputElements`.
     *
     * # Returns
     * A new instance of `DeriveInputElements`.
     */
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        method: Option<&str>,
        request_target: Option<&str>,
        path: Option<&str>,
        target_uri: Option<&str>,
        authority: Option<&str>,
        scheme: Option<&str>,
        query: Option<&str>,
        status: Option<u16>,
    ) -> Self {
        DeriveInputElements {
            method: method.map(|m| m.to_string()),
            request_target: request_target.map(|r| r.to_string()),
            path: path.map(|p| p.to_string()),
            target_uri: target_uri.map(|t| t.to_string()),
            authority: authority.map(|a| a.to_string()),
            scheme: scheme.map(|s| s.to_string()),
            query: query.map(|q| q.to_string()),
            status,
        }
    }
}

/**
 * Key parameters for HTTP signatures.
 */
#[derive(Clone, Debug)]
pub enum SecurityKeyEnum {
    /**
     * The public key used for signature verification.
     */
    PublicKey { contents: Vec<u8>, algorithm: Algorithm, key_id: String },
    /**
     * The shared secret used for hmac signature verification.
     */
    SharedSecret { contents: String, algorithm: Algorithm, key_id: String },
    /**
     * The private key used for signature generation.
     */
    #[allow(dead_code)]
    PrivateKey { contents: Vec<u8>, algorithm: Algorithm, passphrase: Option<String>, key_id: String },
}

impl SecurityKeyEnum {
    /**
     * Returns the algorithm as a string.
     */
    fn get_algorithm_string(&self) -> String {
        match self {
            SecurityKeyEnum::PublicKey { algorithm, .. } => algorithm.to_string(),
            SecurityKeyEnum::SharedSecret { algorithm, .. } => algorithm.to_string(),
            SecurityKeyEnum::PrivateKey { algorithm, .. } => algorithm.to_string(),
        }
    }

    /**
     * Returns the key id as a string.
     */
    fn get_key_id(&self) -> &str {
        match self {
            SecurityKeyEnum::PublicKey { key_id, .. } => key_id,
            SecurityKeyEnum::SharedSecret { key_id, .. } => key_id,
            SecurityKeyEnum::PrivateKey { key_id, .. } => key_id,
        }
    }

    /**
     * Verifies the signature using the appropriate key.
     *
     * This function delegates the verification to the specific
     * key type (public, shared secret, or private).
     *
     * #Arguments
     *
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    pub fn verify_signature(&self, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        match self {
            SecurityKeyEnum::PublicKey { algorithm, contents, key_id: _ } => {
                Self::verify_signature_public_key(algorithm, contents, signature, signature_base)?;
            }
            SecurityKeyEnum::SharedSecret { algorithm: _, contents, key_id: _ } => Self::verify_signature_shared_secret(signature, signature_base, contents.as_bytes())?,
            SecurityKeyEnum::PrivateKey { .. } => {
                return Err(HttpSignaturesError::UnsupportedAlgorithm { details: "Private key verification not supported".into() });
            }
        }
        Ok(())
    }

    /**
     * Generates a private key signature.
     *
     * This function uses the private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_signature(&self, signature_base: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        match self {
            SecurityKeyEnum::PrivateKey { algorithm, contents, passphrase: _, key_id: _ } => Self::generate_signature_private_key(algorithm, contents, signature_base),
            SecurityKeyEnum::SharedSecret { algorithm: _, contents, key_id: _ } => Self::generate_signature_shared_secret(contents.as_bytes(), signature_base),
            SecurityKeyEnum::PublicKey { .. } => Err(HttpSignaturesError::UnsupportedAlgorithm { details: "Public key generation not supported".into() }),
        }
    }

    /**
     * Verifies a public key signature.
     *
     * This function uses the public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `algorithm`: The algorithm used for verification.
     * `public_key`: The public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_signature_public_key(algorithm: &Algorithm, public_key: &[u8], signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let public_key = openssl::pkey::PKey::public_key_from_pem(public_key).map_err(|err| {
            warn!("Failed to read public key: {err}");
            HttpSignaturesError::FailedToReadKey
        })?;
        match algorithm {
            Algorithm::RsaPssSha512 => Self::verify_rsa_pss_sha512(public_key, signature, signature_base)?,
            Algorithm::RsaPkcs1Sha256 => Self::verify_rsa_pkcs1_sha256(public_key, signature, signature_base)?,
            Algorithm::EcdsaP256Sha256 => Self::verify_ecdsa_p256_sha256(public_key, signature, signature_base)?,
            Algorithm::EcdsaP384Sha384 => Self::verify_ecdsa_p384_sha384(public_key, signature, signature_base)?,
            Algorithm::Ed25519 => Self::verify_ed25519(public_key, signature, signature_base)?,
            _ => return Err(HttpSignaturesError::UnsupportedAlgorithm { details: format!("Unsupported algorithm: {algorithm:?}") }),
        };
        Ok(())
    }

    /**
     * Generates a private key signature.
     *
     * This function uses the private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_signature_private_key(algorithm: &Algorithm, private_key: &[u8], signature: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let private_key = openssl::pkey::PKey::private_key_from_pem(private_key).map_err(|err| {
            warn!("Failed to read private key: {err}");
            HttpSignaturesError::FailedToReadKey
        })?;
        let generated_signature = match algorithm {
            Algorithm::RsaPssSha512 => Self::generate_rsa_pss_sha512_signature(private_key, signature)?,
            Algorithm::RsaPkcs1Sha256 => Self::generate_rsa_pkcs1_sha256_signature(private_key, signature)?,
            Algorithm::EcdsaP256Sha256 => Self::generate_ecdsa_p256_sha256_signature(private_key, signature)?,
            Algorithm::EcdsaP384Sha384 => Self::generate_ecdsa_p384_sha384_signature(private_key, signature)?,
            Algorithm::Ed25519 => Self::generate_ed25519_signature(private_key, signature)?,
            _ => return Err(HttpSignaturesError::UnsupportedAlgorithm { details: format!("Unsupported algorithm: {algorithm:?}") }),
        };
        Ok(generated_signature)
    }

    /**
     * Verifies a shared secret signature.
     *
     * This function uses the shared secret to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     * `shared_secret`: The shared secret used to verify the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_signature_shared_secret(signature: &[u8], signature_base: &[u8], shared_secret: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(shared_secret).map_err(|err| {
            warn!("Failed to create HMAC: {err}");
            HttpSignaturesError::HmacError
        })?;
        hmac.update(signature_base);
        hmac.verify_slice(signature).map_err(|err| {
            warn!("Failed to verify HMAC: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        Ok(())
    }

    /**
     * Generates a shared secret signature.
     *
     * This function uses the shared secret to generate a signature
     * for the provided signature base.
     *
     * #Arguments
     *
     * `shared_secret`: The shared secret used to generate the signature.
     * `signature_base`: The base data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_signature_shared_secret(shared_secret: &[u8], signature_base: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(shared_secret).map_err(|err| {
            warn!("Failed to create HMAC: {err}");
            HttpSignaturesError::HmacError
        })?;
        hmac.update(signature_base);
        let signature = hmac.finalize().into_bytes();
        Ok(signature.to_vec())
    }

    /**
     * Verifies an RSA PSS SHA-512 signature.
     *
     * This function uses the RSA public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `public_key`: The RSA public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_rsa_pss_sha512(public_key: PKey<Public>, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha512(), &public_key).map_err(|err| {
            warn!("Failed to create verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(|err| {
            warn!("Failed to set RSA padding: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        verifier.update(signature_base).map_err(|err| {
            warn!("Failed to update verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        let result = verifier.verify(signature).map_err(|err| {
            warn!("Failed to verify signature: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        if !result {
            return Err(HttpSignaturesError::SignatureVerificationFailed { details: "Invalid signature".into() });
        }
        Ok(())
    }

    /**
     * Generates an RSA PSS SHA-512 signature.
     *
     * This function uses the RSA private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The RSA private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_rsa_pss_sha512_signature(private_key: PKey<Private>, signature_data: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha512(), &private_key).map_err(|err| {
            warn!("Failed to create signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS).map_err(|err| {
            warn!("Failed to set RSA padding: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.update(signature_data).map_err(|err| {
            warn!("Failed to update signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        let signature = signer.sign_to_vec().map_err(|err| {
            warn!("Failed to sign data: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        Ok(signature)
    }

    /**
     * Verifies an RSA PKCS#1 SHA-256 signature.
     *
     * This function uses the RSA public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `public_key`: The RSA public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_rsa_pkcs1_sha256(public_key: PKey<Public>, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key).map_err(|err| {
            warn!("Failed to create verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        verifier.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|err| {
            warn!("Failed to set RSA padding: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        verifier.update(signature_base).map_err(|err| {
            warn!("Failed to update verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        let result = verifier.verify(signature).map_err(|err| {
            warn!("Failed to verify RSA PKCS#1 SHA-256 signature: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        if !result {
            return Err(HttpSignaturesError::SignatureVerificationFailed { details: "Invalid signature".into() });
        }
        Ok(())
    }

    /**
     * Generates an RSA PKCS#1 SHA-256 signature.
     *
     * This function uses the RSA private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The RSA private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_rsa_pkcs1_sha256_signature(private_key: PKey<Private>, signature_data: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &private_key).map_err(|err| {
            warn!("Failed to create signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.set_rsa_padding(openssl::rsa::Padding::PKCS1).map_err(|err| {
            warn!("Failed to set RSA padding: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.update(signature_data).map_err(|err| {
            warn!("Failed to update signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        let signature = signer.sign_to_vec().map_err(|err| {
            warn!("Failed to sign data: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        Ok(signature)
    }

    /**
     * Verifies an ECDSA P-256 SHA-256 signature.
     *
     * This function uses the ECDSA P-256 public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `public_key`: The ECDSA P-256 public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_ecdsa_p256_sha256(public_key: PKey<Public>, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &public_key).map_err(|err| {
            warn!("Failed to create verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        let result = verifier.verify_oneshot(signature, signature_base).map_err(|err| {
            warn!("Failed to verify ECDSA P-256 SHA-256 signature: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        if !result {
            return Err(HttpSignaturesError::SignatureVerificationFailed { details: "Invalid signature".into() });
        }
        Ok(())
    }

    /**
     * Generates an ECDSA P-256 SHA-256 signature.
     *
     * This function uses the ECDSA P-256 private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The ECDSA P-256 private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_ecdsa_p256_sha256_signature(private_key: PKey<Private>, signature_data: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &private_key).map_err(|err| {
            warn!("Failed to create signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.update(signature_data).map_err(|err| {
            warn!("Failed to update signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        let signature = signer.sign_to_vec().map_err(|err| {
            warn!("Failed to sign data: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        Ok(signature)
    }

    /**
     * Verifies an ECDSA P-384 SHA-384 signature.
     *
     * This function uses the ECDSA P-384 public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `public_key`: The ECDSA P-384 public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_ecdsa_p384_sha384(public_key: PKey<Public>, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &public_key).map_err(|err| {
            warn!("Failed to create verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        let result = verifier.verify_oneshot(signature, signature_base).map_err(|err| {
            warn!("Failed to verify ECDSA P-384 SHA-384 signature: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        if !result {
            return Err(HttpSignaturesError::SignatureVerificationFailed { details: "Invalid signature".into() });
        }
        Ok(())
    }

    /**
     * Generates an ECDSA P-384 SHA-384 signature.
     *
     * This function uses the ECDSA P-384 private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The ECDSA P-384 private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_ecdsa_p384_sha384_signature(private_key: PKey<Private>, signature_data: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha384(), &private_key).map_err(|err| {
            warn!("Failed to create signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        signer.update(signature_data).map_err(|err| {
            warn!("Failed to update signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        let signature = signer.sign_to_vec().map_err(|err| {
            warn!("Failed to sign data: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        Ok(signature)
    }

    /**
     * Verifies an Ed25519 signature.
     *
     * This function uses the Ed25519 public key to verify the signature
     * against the provided signature base.
     *
     * #Arguments
     *
     * `public_key`: The Ed25519 public key used to verify the signature.
     * `signature`: The signature to verify.
     * `signature_base`: The base data used to create the signature.
     *
     * #Returns
     *
     * This function returns `Ok(())` if the signature is valid, or an error
     * if the signature is invalid.
     */
    fn verify_ed25519(public_key: PKey<Public>, signature: &[u8], signature_base: &[u8]) -> Result<(), HttpSignaturesError> {
        let mut verifier = openssl::sign::Verifier::new_without_digest(&public_key).map_err(|err| {
            warn!("Failed to create verifier: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        let result = verifier.verify_oneshot(signature, signature_base).map_err(|err| {
            warn!("Failed to verify Ed25519 signature: {err}");
            HttpSignaturesError::SignatureVerificationFailed { details: err.to_string() }
        })?;
        if !result {
            return Err(HttpSignaturesError::SignatureVerificationFailed { details: "Invalid signature".into() });
        }
        Ok(())
    }

    /**
     * Generates an Ed25519 signature.
     *
     * This function uses the Ed25519 private key to generate a signature
     * for the provided signature data.
     *
     * #Arguments
     *
     * `private_key`: The Ed25519 private key used to generate the signature.
     * `signature_data`: The data to sign.
     *
     * #Returns
     *
     * This function returns a `Result` containing the generated signature
     * or an error if the signature generation fails.
     */
    fn generate_ed25519_signature(private_key: PKey<Private>, signature_data: &[u8]) -> Result<Vec<u8>, HttpSignaturesError> {
        let mut signer = openssl::sign::Signer::new_without_digest(&private_key).map_err(|err| {
            warn!("Failed to create signer: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        let signature = signer.sign_oneshot_to_vec(signature_data).map_err(|err| {
            warn!("Failed to sign data: {err}");
            HttpSignaturesError::SignatureGenerationFailed { details: err.to_string() }
        })?;
        Ok(signature)
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
    SignatureVerificationFailed { details: String },
    /**
     * Error indicating that the signature has expired. The expired timestamp is provided.
     */
    SignatureExpired { expired: usize },
    /**
     * Error indicating that the key could not be read from byte data.
     */
    FailedToReadKey,
    /**
     * Error indicating that the HMAC data could not be generated.
     */
    HmacError,
    /**
     * Error indicating that the algorithm is not supported.
     */
    UnsupportedAlgorithm { details: String },
    /**
     * Error indicating that the signature generation failed.
     */
    SignatureGenerationFailed { details: String },
    /**
     * Error indicating that the generating secret is missing, but configuration is present.
     */
    MissingGeneratingSecret,
}

impl Display for HttpSignaturesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpSignaturesError::InvalidSignatureFormat => write!(f, "Invalid signature format"),
            HttpSignaturesError::KeyNotFound { keyid } => write!(f, "Key not found: {keyid}"),
            HttpSignaturesError::MissingExpiresTimestamp => write!(f, "Missing expires timestamp"),
            HttpSignaturesError::MissingSignatureHeader => write!(f, "Missing signature header"),
            HttpSignaturesError::MissingSignatureInputHeader => write!(f, "Missing signature input header"),
            HttpSignaturesError::MissingCreatedTimestamp => write!(f, "Missing created timestamp"),
            HttpSignaturesError::MissingRequiredHeader => write!(f, "Missing required header"),
            HttpSignaturesError::MissingRequiredDerivedValue => write!(f, "Missing required derived value"),
            HttpSignaturesError::MissingAlgorithm => write!(f, "Missing algorithm"),
            HttpSignaturesError::MissingKeyId => write!(f, "Missing key ID"),
            HttpSignaturesError::MissingHeaderInRequest { name } => write!(f, "Missing header in request: {name}"),
            HttpSignaturesError::NoSignatureElements => write!(f, "No signature elements"),
            HttpSignaturesError::SignatureVerificationFailed { details } => write!(f, "Signature verification failed: {details}"),
            HttpSignaturesError::SignatureExpired { expired } => write!(f, "Signature expired at timestamp: {expired}"),
            HttpSignaturesError::FailedToReadKey => write!(f, "Failed to read key"),
            HttpSignaturesError::HmacError => write!(f, "HMAC error"),
            HttpSignaturesError::UnsupportedAlgorithm { details } => write!(f, "Unsupported algorithm: {details}"),
            HttpSignaturesError::SignatureGenerationFailed { details } => write!(f, "Signature generation failed: {details}"),
            HttpSignaturesError::MissingGeneratingSecret => write!(f, "Missing generating secret"),
        }
    }
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
 * Represents the requirements for generating a signature.
 */
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GenerationRequirement {
    /**
     * Represents a header that is required in the signature if included in request/response.
     */
    HeaderRequiredIfIncluded { name: String },
    /**
     * Represents a header that is required in the signature if the body is present.
     */
    HeaderRequiredIfBodyPresent { name: String },
    /**
     * Is required required for the signature input.
     */
    GenerateCreated,
    /**
     * Is the expires required for the signature input.
     */
    GenerateExpires { expires_secs: usize },
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
    Status {
        value: String,
    },
}

#[derive(Debug)]
struct SignatureOutput {
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

impl SignatureOutput {
    /**
     * Creates a new `SignatureOutput` instance.
     * This function initializes the signature output with the provided headers, derived elements,
     * requirements, key ID, algorithm, and body presence flag.
     *
     * # Algorithms
     * `headers`: A map of header names to their values.
     * `derive_elements`: The elements derived from the request for signature generation.
     * `requirements`: The requirements that must be met for the signature.
     * `keyid`: The key ID to use for the signature.
     * `alg`: The algorithm to use for the signature.
     * `has_body`: Whether the request has a body.
     *
     */
    fn new(headers: &HashMap<String, String>, derive_elements: &DeriveInputElements, requirements: &HashSet<GenerationRequirement>, keyid: &str, alg: &str, has_body: bool) -> Self {
        let mut sig: Vec<SignatureElementEnum> = Vec::new();
        let mut created = None;
        let mut expires = None;
        for requirement in requirements {
            match requirement {
                GenerationRequirement::HeaderRequiredIfIncluded { name } => {
                    if headers.contains_key(name) {
                        sig.push(SignatureElementEnum::HeaderString { name: name.clone(), value: headers.get(name).cloned().unwrap_or_default() });
                    }
                }
                GenerationRequirement::HeaderRequiredIfBodyPresent { name } => {
                    if has_body && headers.contains_key(name) {
                        sig.push(SignatureElementEnum::HeaderString { name: name.clone(), value: headers.get(name).cloned().unwrap_or_default() });
                    }
                }
                GenerationRequirement::GenerateCreated => {
                    if headers.get("created").is_none() {
                        created = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as usize);
                    }
                }
                GenerationRequirement::GenerateExpires { expires_secs } => {
                    if headers.get("expires").is_none() {
                        expires = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as usize + expires_secs);
                    }
                }
                GenerationRequirement::DerivedRequired { name } => match name.as_str() {
                    "@method" => {
                        if let Some(method) = derive_elements.method.as_ref() {
                            sig.insert(0, SignatureElementEnum::Method { value: method.clone() });
                        }
                    }
                    "@request-target" => {
                        if let Some(request_target) = derive_elements.request_target.as_ref() {
                            sig.insert(0, SignatureElementEnum::RequestTarget { value: request_target.clone() });
                        }
                    }
                    "@query" => {
                        if let Some(query) = derive_elements.query.as_ref() {
                            sig.insert(0, SignatureElementEnum::Query { value: query.clone() });
                        }
                    }
                    "@path" => {
                        if let Some(path) = derive_elements.path.as_ref() {
                            sig.insert(0, SignatureElementEnum::Path { value: path.clone() });
                        }
                    }
                    "@target-uri" => {
                        if let Some(target_uri) = derive_elements.target_uri.as_ref() {
                            sig.insert(0, SignatureElementEnum::TargetUri { value: target_uri.clone() });
                        }
                    }
                    "@authority" => {
                        if let Some(authority) = derive_elements.authority.as_ref() {
                            sig.insert(0, SignatureElementEnum::Authority { value: authority.clone() });
                        }
                    }
                    "@scheme" => {
                        if let Some(scheme) = derive_elements.scheme.as_ref() {
                            sig.insert(0, SignatureElementEnum::Scheme { value: scheme.clone() });
                        }
                    }
                    "@status" => {
                        if let Some(status) = derive_elements.status.as_ref() {
                            sig.insert(0, SignatureElementEnum::Status { value: (*status.to_string()).into() });
                        }
                    }
                    _ => {}
                },
            }
        }
        SignatureOutput { sig, alg: alg.to_string(), keyid: keyid.to_string(), created, expires }
    }

    /**
     * Returns the signature parameters as a string.
     *
     * The sig= is not included.
     * Example: sig=("date" "content-type" "content-digest" "@method" "@request-target");alg="rsa-pss-sha512";keyid="keyid";created=1754334782;expires=1754335082
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
                SignatureElementEnum::Status { value: _ } => {
                    signature_params.push_str("\"@status\"");
                }
            }
        }
        signature_params.push_str(");alg=\"");
        signature_params.push_str(&self.alg);
        signature_params.push_str("\";keyid=\"");
        signature_params.push_str(&self.keyid);
        signature_params.push('\"');
        if let Some(created) = self.created {
            signature_params.push_str(&format!(";created={created}"));
        }
        if let Some(expires) = self.expires {
            signature_params.push_str(&format!(";expires={expires}"));
        }
        debug!("Signature Params: {}", signature_params);
        signature_params
    }

    fn get_signature_base(&self) -> String {
        let mut signature_base = String::new();
        for element in &self.sig {
            match element {
                SignatureElementEnum::HeaderString { name, value } => {
                    signature_base.push_str(&format!("\"{}\": {}", name.to_lowercase(), value));
                }
                SignatureElementEnum::Method { value } => {
                    signature_base.push_str(&format!("\"@method\": {}", value.to_uppercase()));
                }
                SignatureElementEnum::RequestTarget { value } => {
                    signature_base.push_str(&format!("\"@request-target\": {}", value.to_lowercase()));
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
                SignatureElementEnum::Status { value } => {
                    signature_base.push_str(&format!("\"@status\": {value}"));
                }
            }
            signature_base.push('\n');
        }
        signature_base.push_str(&format!("\"@signature-params\": {}", self.get_signature_params()));
        debug!("Output Signature Base: \n{}", signature_base);
        signature_base
    }
}

/**
 * Represents the signature input.
 * Example: Signature-Input: sig=("date" "content-type" "content-digest" "@method" "@request-target");alg="rsa-pss-sha512";keyid="keyid";created=1754334782;expires=1754335082
 */
#[derive(Debug)]
struct SignatureInput {
    original_signature_input: String,
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
    fn new(headers: &HashMap<String, String>, derive_elements: &DeriveInputElements, requirements: &HashSet<VerificationRequirement>, has_body: bool) -> Result<Self, HttpSignaturesError> {
        let signature_input = headers.get("signature-input").ok_or(HttpSignaturesError::MissingSignatureInputHeader)?;
        let original_signature_input = signature_input.clone().replace("sig=", "");
        let (sig, alg, keyid, created, expires) = Self::get_signature_elements(headers, derive_elements, signature_input);
        Self::verify_created_requirement(requirements, created)?;
        Self::verify_expires_requirement(requirements, expires)?;
        Self::verify_empty_signature_elements(&sig)?;
        Self::verify_body_headers(requirements, has_body, &sig)?;
        Self::verify_headers(requirements, &sig)?;
        Self::verify_headers_if_included_in_request(requirements, &sig, headers)?;
        Self::verify_derived(requirements, &sig)?;
        Self::check_expired(requirements, expires)?;
        Self::verify_algorithm(&alg)?;
        Self::verify_keyid(&keyid)?;
        Self::verify_request_headers(headers, &sig)?;
        Ok(SignatureInput { original_signature_input, sig, alg, keyid })
    }

    /**
     * Returns a string representation of the signature parameters.
     *
     * This method constructs a string that includes all signature elements
     * formatted as "name=value" pairs, suitable for use in signature verification.
     */
    #[allow(dead_code)]
    fn get_signature_params(&self) -> String {
        self.original_signature_input.clone()
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
                SignatureElementEnum::Status { value } => {
                    signature_base.push_str(&format!("\"@status\": {value}"));
                }
            }
            signature_base.push('\n');
        }
        signature_base.push_str(&format!("\"@signature-params\": {}", self.original_signature_input));
        debug!("Input Signature Base: \n{signature_base}");
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
    fn get_signature_elements(
        headers: &HashMap<String, String>,
        derive_elements: &DeriveInputElements,
        signature_input: &str,
    ) -> (Vec<SignatureElementEnum>, String, String, Option<usize>, Option<usize>) {
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
    fn parse_signature_element(headers: &HashMap<String, String>, derive_elements: &DeriveInputElements, part: &str) -> Vec<SignatureElementEnum> {
        let mut sig = Vec::new();
        let value = between(part, "sig=(", ")").unwrap_or_default();
        for element in value.replace("\"", "").split_whitespace() {
            if element.starts_with('@') {
                if element == "@method" {
                    sig.push(SignatureElementEnum::Method { value: derive_elements.method.clone().unwrap_or_default() });
                } else if element == "@request-target" {
                    sig.push(SignatureElementEnum::RequestTarget { value: derive_elements.request_target.clone().unwrap_or_default() });
                } else if element == "@query" {
                    sig.push(SignatureElementEnum::Query { value: derive_elements.query.clone().unwrap_or_default() });
                } else if element == "@path" {
                    sig.push(SignatureElementEnum::Path { value: derive_elements.path.clone().unwrap_or_default() });
                } else if element == "@target-uri" {
                    sig.push(SignatureElementEnum::TargetUri { value: derive_elements.target_uri.clone().unwrap_or_default() });
                } else if element == "@authority" {
                    sig.push(SignatureElementEnum::Authority { value: derive_elements.authority.clone().unwrap_or_default() });
                } else if element == "@scheme" {
                    sig.push(SignatureElementEnum::Scheme { value: derive_elements.scheme.clone().unwrap_or_default() });
                } else if element == "@status" {
                    sig.push(SignatureElementEnum::Status { value: derive_elements.status.unwrap_or_default().to_string() });
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
                if name == "@status" {
                    derived = sig.iter().any(|f| matches!(f, SignatureElementEnum::Status { .. }));
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
    fn check_expired(requirements: &HashSet<VerificationRequirement>, expires: Option<usize>) -> Result<(), HttpSignaturesError> {
        if requirements.contains(&VerificationRequirement::CheckExpired)
            && let Some(expiry) = expires
            && expiry < chrono::Utc::now().timestamp() as usize
        {
            return Err(HttpSignaturesError::SignatureExpired { expired: expiry });
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
            if let SignatureElementEnum::HeaderString { name, .. } = element
                && !headers.contains_key(name)
            {
                return Err(HttpSignaturesError::MissingHeaderInRequest { name: name.clone() });
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
        fs, vec,
    };

    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, RSA_PKCS1_SHA256, RSA_PSS_SHA512, RsaKeyPair},
    };

    use super::*;

    #[tokio::test]
    async fn test_missing_request_signature() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .is_ok()
        );
        assert_eq!(SignatureInput::new(&HashMap::from([]), &derive_elements, &requirements, false).unwrap_err(), HttpSignaturesError::MissingSignatureInputHeader);
    }

    #[tokio::test]
    async fn test_missing_request_created() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::CreatedRequired);
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";expires=1754335082".to_string()
                )]),
                &derive_elements,
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingCreatedTimestamp
        );
    }

    #[tokio::test]
    async fn test_missing_request_expires() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::ExpiresRequired);
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782".to_string()
                )]),
                &derive_elements,
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingExpiresTimestamp
        );
    }

    #[tokio::test]
    async fn test_missing_request_accept() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
        let mut requirements: HashSet<VerificationRequirement> = HashSet::new();
        requirements.insert(VerificationRequirement::HeaderRequired { name: "accept".into() });
        assert_eq!(
            SignatureInput::new(
                &HashMap::from([(
                    "signature-input".to_string(),
                    "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"keyid\";created=1754334782;expires=0".to_string()
                )]),
                &derive_elements,
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_request_missing_required_body_content_length() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                true
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_request_missing_required_header_date() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_request_missing_derived() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredDerivedValue
        );
    }

    #[tokio::test]
    async fn test_request_check_expired() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::SignatureExpired { expired: 1554335082 }
        );
    }

    #[tokio::test]
    async fn test_request_check_required_header_if_included_in_request_failure() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .unwrap_err(),
            HttpSignaturesError::MissingRequiredHeader
        );
    }

    #[tokio::test]
    async fn test_request_check_required_header_if_included_in_request_success() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);
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
                &requirements,
                false
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_request_full_test() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);

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
                &requirements,
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
    async fn test_request_signature_input_with_body() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);

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

        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, true).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
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
    async fn test_response_signature_input_with_body() {
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(200));

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746".to_string(),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:".to_string());
        headers.insert("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        headers.insert("created".to_string(), "1754065546".to_string());

        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, true).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.sig.len(), 4);

        let signature_params = parsed.get_signature_params();
        assert_eq!(signature_params.as_str(), "(\"date\" \"content-type\" \"content-digest\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746");

        let signature_base = parsed.get_signature_base();
        assert_eq!(
            signature_base,
            "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"content-type\": application/json
\"content-digest\": SHA-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:
\"@status\": 200
\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754065546;expires=1754066746"
        );
    }

    #[tokio::test]
    async fn test_request_signature_input_no_body() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/api/v1/resource"), None, None, None, None, None, None);

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("signature-input".to_string(), "sig=(\"date\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".to_string());
        headers.insert("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        headers.insert("created".to_string(), "1754065546".to_string());

        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, false).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
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
    async fn test_response_signature_input_no_body() {
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(200));

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("signature-input".to_string(), "sig=(\"date\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488".to_string());
        headers.insert("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        headers.insert("created".to_string(), "1754065546".to_string());

        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, false).unwrap();
        assert_eq!(parsed.alg, "rsa-pss-sha512");
        assert_eq!(parsed.keyid, "key123");
        assert_eq!(parsed.sig.len(), 2);

        let signature_params = parsed.get_signature_params();
        assert_eq!(signature_params.as_str(), "(\"date\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488");

        let signature_base = parsed.get_signature_base();
        assert_eq!(
            signature_base,
            "\"date\": Mon, 01 Jan 2024 00:00:00 GMT
\"@status\": 200
\"@signature-params\": (\"date\" \"@status\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754175188;expires=1754175488"
        );
    }

    #[tokio::test]
    async fn test_request_verify_success_rsa_pss_sha512() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::PublicKey { contents: public_key, algorithm: Algorithm::RsaPssSha512, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_verify_success_rsa_v1_5_sha256() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::PublicKey { contents: public_key, algorithm: Algorithm::RsaPkcs1Sha256, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_verify_success_ecdsa_p256_sha256() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::PublicKey { contents: public_key, algorithm: Algorithm::EcdsaP256Sha256, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_verify_success_ecdsa_p384_sha384() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::PublicKey { contents: public_key, algorithm: Algorithm::EcdsaP384Sha384, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_verify_success_ed25519() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key4.pem").unwrap(), algorithm: Algorithm::Ed25519, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_verify_success_hmac_sha256() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

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

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::SharedSecret { contents: "TestHMACKey".to_string(), algorithm: Algorithm::HmacSha256, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_response_verify_success_hmac_sha256() {
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(200));

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let signature_str = "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"content-type\": application/json\n\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n\"@status\": 200\n\"@signature-params\": (\"date\" \"content-type\" \"content-digest\" \"@status\");alg=\"hmac-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string();

        let signature = STANDARD.encode(ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"TestHMACKey"), signature_str.as_bytes()));

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@status\");alg=\"hmac-sha256\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("signature".to_string(), format!("sig=:{signature}:").to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());

        let mut keys: HashMap<String, SecurityKeyEnum> = HashMap::new();
        keys.insert("key123".to_string(), SecurityKeyEnum::SharedSecret { contents: "TestHMACKey".to_string(), algorithm: Algorithm::HmacSha256, key_id: "key123".to_string() });
        let service = HttpSignaturesService::new(None, None, Some(requirements), keys);
        let result = service.verify_signature(&headers, &derive_elements);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_request_parse_signature_elements_success() {
        let derive_elements = DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), None, None, None, None, None, None);

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@request-target\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, false).unwrap();
        assert_eq!(parsed.sig.len(), 5);
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "date")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-type")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::HeaderString { name, .. } if name == "content-digest")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::Method { value: val } if val == "POST")));
        assert!(parsed.sig.iter().any(|e| matches!(e, SignatureElementEnum::RequestTarget { value: val } if val == "/foo?param=value&pet=dog")));
    }

    #[tokio::test]
    async fn test_request_parse_signature_elements_success_all_derived() {
        let derive_elements =
            DeriveInputElements::new(Some("POST"), Some("/foo?param=value&pet=dog"), Some("/foo"), Some("/foo"), Some("example.com"), Some("https"), Some("?param=value&pet=dog"), None);

        let requirements: HashSet<VerificationRequirement> = HashSet::new();

        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert(
            "signature-input".to_string(),
            "sig=(\"date\" \"content-type\" \"content-digest\" \"@method\" \"@target-uri\" \"@request-target\" \"@path\" \"@authority\" \"@scheme\" \"@query\");alg=\"rsa-pss-sha512\";keyid=\"key123\";created=1754409493;expires=1754409793".to_string(),
        );
        headers.insert("date".to_string(), "Tue, 20 Apr 2021 02:07:55 GMT".to_string());
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-digest".to_string(), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:".to_string());
        let parsed = SignatureInput::new(&headers, &derive_elements, &requirements, false).unwrap();
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
    async fn test_generate_signature_rsa_pss_sha512() {
        let security_enum_private_key =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key1.pem").unwrap(), algorithm: Algorithm::RsaPssSha512, passphrase: None, key_id: "key123".to_string() };
        let security_key_public_key = SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key1.pem").unwrap(), algorithm: Algorithm::RsaPssSha512, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_generate_signature_rsa_pkcs1_sha256() {
        let security_enum_private_key =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key2.pem").unwrap(), algorithm: Algorithm::RsaPkcs1Sha256, passphrase: None, key_id: "key123".to_string() };
        let security_key_public_key =
            SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key2.pem").unwrap(), algorithm: Algorithm::RsaPkcs1Sha256, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_generate_signature_ecdsa_p256_sha256() {
        let security_enum_private_key =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key5.pem").unwrap(), algorithm: Algorithm::EcdsaP256Sha256, passphrase: None, key_id: "key123".to_string() };
        let security_key_public_key =
            SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key5.pem").unwrap(), algorithm: Algorithm::EcdsaP256Sha256, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_generate_signature_ecdsa_p384_sha384() {
        let security_enum_private_key =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key6.pem").unwrap(), algorithm: Algorithm::EcdsaP384Sha384, passphrase: None, key_id: "key123".to_string() };
        let security_key_public_key =
            SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key6.pem").unwrap(), algorithm: Algorithm::EcdsaP384Sha384, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_generate_signature_ed25519() {
        let security_enum_private_key =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key4.pem").unwrap(), algorithm: Algorithm::Ed25519, passphrase: None, key_id: "key123".to_string() };
        let security_key_public_key = SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key4.pem").unwrap(), algorithm: Algorithm::Ed25519, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_generate_signature_hmac_sha256() {
        let security_enum_private_key = SecurityKeyEnum::SharedSecret { contents: "Test secret".to_string(), algorithm: Algorithm::HmacSha256, key_id: "key123".to_string() };
        let security_key_public_key = SecurityKeyEnum::SharedSecret { contents: "Test secret".to_string(), algorithm: Algorithm::HmacSha256, key_id: "key123".to_string() };
        let signature = security_enum_private_key.generate_signature(b"test data").unwrap();
        let verify = security_key_public_key.verify_signature(&signature, b"test data");
        assert!(verify.is_ok());
    }

    #[tokio::test]
    async fn test_signature_output_format_no_body() {
        let headers: HashMap<String, String> = vec![("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string())].into_iter().collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(204));
        let requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
        ]
        .into_iter()
        .collect();
        let signature_output = SignatureOutput::new(&headers, &derive_elements, &requirements, "key123", "rsa-pss-sha512", false);
        assert!(signature_output.get_signature_params().starts_with("(\"@status\" \"date\");alg=\"rsa-pss-sha512\";keyid=\"key123\";"));
        assert!(signature_output.get_signature_params().contains("created"));
        assert!(signature_output.get_signature_params().contains("expires"));
    }

    #[tokio::test]
    async fn test_signature_output_format_body() {
        let headers: HashMap<String, String> = vec![
            ("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "123".to_string()),
            ("content-digest".to_string(), "sha256=abcdef1234567890".to_string()),
        ]
        .into_iter()
        .collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(204));
        let requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();
        let signature_output = SignatureOutput::new(&headers, &derive_elements, &requirements, "key123", "rsa-pss-sha512", true);
        assert!(signature_output.get_signature_params().contains("\"@status\""));
        assert!(signature_output.get_signature_params().contains("\"date\""));
        assert!(signature_output.get_signature_params().contains("\"content-type\""));
        assert!(signature_output.get_signature_params().contains("\"content-digest\""));
        assert!(signature_output.get_signature_params().contains("created"));
        assert!(signature_output.get_signature_params().contains("expires"));
    }

    #[tokio::test]
    async fn test_signature_output_format_no_created_and_no_expires() {
        let headers: HashMap<String, String> = vec![
            ("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "123".to_string()),
            ("content-digest".to_string(), "sha256=abcdef1234567890".to_string()),
        ]
        .into_iter()
        .collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(204));
        let requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();
        let signature_output = SignatureOutput::new(&headers, &derive_elements, &requirements, "key123", "rsa-pss-sha512", true);
        assert!(signature_output.get_signature_params().contains("\"@status\""));
        assert!(signature_output.get_signature_params().contains("\"date\""));
        assert!(signature_output.get_signature_params().contains("\"content-type\""));
        assert!(signature_output.get_signature_params().contains("\"content-digest\""));
        assert!(!signature_output.get_signature_params().contains("created"));
        assert!(!signature_output.get_signature_params().contains("expires"));
    }

    #[tokio::test]
    async fn test_generate_signature_base_no_body() {
        let headers: HashMap<String, String> = vec![("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string())].into_iter().collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(204));
        let requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
        ]
        .into_iter()
        .collect();
        let signature_output = SignatureOutput::new(&headers, &derive_elements, &requirements, "key123", "rsa-pss-sha512", false);
        let signature_base = signature_output.get_signature_base();
        assert!(signature_base.starts_with("\"@status\": 204\n\"date\": Mon, 01 Jan 2024 00:00:00 GMT\n\"@signature-params\": (\"@status\" \"date\");alg=\"rsa-pss-sha512\";keyid=\"key123\""));
    }

    #[tokio::test]
    async fn test_generate_signature_base_body() {
        let headers: HashMap<String, String> = vec![
            ("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "123".to_string()),
            ("content-digest".to_string(), "sha256=abcdef1234567890".to_string()),
        ]
        .into_iter()
        .collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(204));
        let requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();
        let signature_output = SignatureOutput::new(&headers, &derive_elements, &requirements, "key123", "rsa-pss-sha512", true);
        let signature_base = signature_output.get_signature_base();
        assert!(signature_base.contains("\"@status\""));
        assert!(signature_base.contains("\"date\""));
        assert!(signature_base.contains("\"content-type\""));
        assert!(signature_base.contains("\"content-digest\""));
        assert!(signature_base.contains("created"));
        assert!(signature_base.contains("expires"));
    }

    #[tokio::test]
    async fn test_signature_input_equals_output() {
        let verify_requirements: HashSet<VerificationRequirement> = vec![
            VerificationRequirement::HeaderRequired { name: "date".to_string() },
            VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
            VerificationRequirement::DerivedRequired { name: "@status".to_string() },
        ]
        .into_iter()
        .collect();

        let generate_requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();

        let mut headers: HashMap<String, String> = vec![
            ("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "123".to_string()),
            ("content-digest".to_string(), "sha256=:abcdef1234567890:".to_string()),
        ]
        .into_iter()
        .collect();

        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(200));

        let signature_output = SignatureOutput::new(&headers, &derive_elements, &generate_requirements, "key123", "rsa-pss-sha512", true);

        headers.insert("signature".to_string(), "sig=:test:".to_string());
        headers.insert("signature-input".to_string(), format!("sig={}", signature_output.get_signature_params()));
        let signature_input = SignatureInput::new(&headers, &derive_elements, &verify_requirements, true).unwrap();
        assert_eq!(signature_output.get_signature_params(), signature_input.get_signature_params());
        assert_eq!(signature_output.get_signature_base(), signature_input.get_signature_base());
    }

    #[tokio::test]
    async fn test_generate_verify_rsa_pss_sha512_response() {
        let generating_secret =
            SecurityKeyEnum::PrivateKey { contents: fs::read("test_config/keys/private_key1.pem").unwrap(), algorithm: Algorithm::RsaPssSha512, passphrase: None, key_id: "key123".to_string() };

        let verifying_secret = SecurityKeyEnum::PublicKey { contents: fs::read("test_config/keys/public_key1.pem").unwrap(), algorithm: Algorithm::RsaPssSha512, key_id: "key123".to_string() };

        let verify_requirements: HashSet<VerificationRequirement> = vec![
            VerificationRequirement::HeaderRequired { name: "date".to_string() },
            VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();

        let generate_requirements: HashSet<GenerationRequirement> = vec![
            GenerationRequirement::GenerateCreated,
            GenerationRequirement::GenerateExpires { expires_secs: 3600 },
            GenerationRequirement::HeaderRequiredIfIncluded { name: "date".to_string() },
            GenerationRequirement::DerivedRequired { name: "@status".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-type".to_string() },
            GenerationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
        ]
        .into_iter()
        .collect();

        let http_signatures_service =
            HttpSignaturesService::new(Some(generating_secret), Some(generate_requirements), Some(verify_requirements), vec![("key123".to_string(), verifying_secret)].into_iter().collect());

        let mut headers: HashMap<String, String> = vec![
            ("date".to_string(), "Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "123".to_string()),
            ("content-digest".to_string(), "sha256=:abcdef1234567890:".to_string()),
        ]
        .into_iter()
        .collect();
        let derive_elements = DeriveInputElements::new(None, None, None, None, None, None, None, Some(200));
        let signature = http_signatures_service.generate_response_signature(&headers, &derive_elements).unwrap().unwrap();
        headers.insert("signature".to_string(), signature.0);
        headers.insert("signature-input".to_string(), signature.1);
        http_signatures_service.verify_signature(&headers, &derive_elements).unwrap();
    }
}
