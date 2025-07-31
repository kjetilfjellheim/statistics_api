use actix_web::{body::MessageBody, dev::{Payload, ServiceRequest, ServiceResponse}, middleware::Next, web::Bytes, Error};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::debug;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::model::apperror::ApplicationError;

/**
 * Middleware for timing requests.
 */
pub async fn timing_middleware(
    request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let start_time = std::time::Instant::now();
    let path = &request.path().to_owned();
    let method = &request.method().to_owned();
    let response = next.call(request).await;
    let response_code = match &response {
        Ok(service_response) => service_response.status().as_u16(),
        Err(_) => 500, // If there's an error, we assume a server error
    };
    let duration = start_time.elapsed();
    debug!(target: "performance", "Request for {} {} with status {} processed in {:?}ms", method, path, response_code, duration.as_millis());
    response
}

/**
 * Middleware for verifying digest headers.
 */
pub async fn digest_verification_middleware(
    mut request: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let body = request.extract::<Bytes>().await?;
    let body = body.as_ref();
    if body.is_empty() {
        return next.call(request).await;
    }
    let digest_header = request.headers().get("Content-Digest");
    if let Some(digest) = digest_header {
        let digest = digest.to_str().map_err(|_| ApplicationError::new(crate::model::apperror::ErrorType::Application, "Invalid digest header".to_string()))?;
        verify_digest(digest, body)?;
        let bytes = Bytes::copy_from_slice(body);
        let payload = Payload::from(bytes);
        request.set_payload(payload);
        return next.call(request).await;
    }
    Err(ApplicationError::new(crate::model::apperror::ErrorType::DigestVerification, "Missing Content-Digest header".to_string()).into())
}

/**
 * Verify the digest of the request body.   
 * 
 * # Arguments
 * `digest`: The digest header value, expected to be in the format "SHA-256=base64hash".
 * `body`: The request body as a byte slice.
 */
fn verify_digest(digest: &str, body: &[u8]) -> Result<(), ApplicationError> {
    let (algorithm, expected_digest) = digest.split_once('=')
        .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::Application, "Invalid digest format".to_string()))?;
    let expected_hash = str::replace(expected_digest, ":", "");
    let hash_result = match algorithm.to_uppercase().as_str() {
        "SHA-256" => {
            Sha256::digest(body).to_vec()
        },
        "SHA-384" => {
            let mut algorithm = Sha384::new();
            algorithm.update(body);
            algorithm.finalize().to_vec()
        },
        "SHA-512" => {
            let mut algorithm = Sha512::new();
            algorithm.update(body);
            algorithm.finalize().to_vec()
        },
        _ => return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, "Unsupported digest algorithm".to_string()).into()),
    };
    let result = STANDARD.encode(hash_result);
    if result == expected_hash {
        Ok(())
    } else {
        println!("Expected: {}, Got: {}", expected_hash, result);
        Err(ApplicationError::new(crate::model::apperror::ErrorType::DigestVerification, "Digest verification failed".to_string()).into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_verify_digest_sha256() {
        let body = b"h";        
        assert!(verify_digest("sha-256=:qqlAJmTxpB9A67xSyZk+tmrrNmYClY/fqig7ceZNsSM=:", body).is_ok());
    }

    #[tokio::test]
    async fn test_verify_digest_sha512() {
        let body = b"{\"hello\":\"world\"}";        
        assert!(verify_digest("sha-512=:+PtokCNHosgo04ww4cNhd4yJxhMjLzWjDAKtKwQZDT4Ef9v/PrS/+BQLX4IX5dZkUMK/tQo7Uyc68RkhNyCZVg==:", body).is_ok());
    }

    #[tokio::test]
    async fn test_verify_digest_failure() {
        let body = b"test body";
        let digest = "SHA-256=invalidhash";
        assert!(verify_digest(digest, body).is_err());
    }

    #[tokio::test]
    async fn test_verify_digest_unsupported_algorithm() {
        let body = b"test body";
        let digest = "SHA-1024=invalidhash";
        assert!(verify_digest(digest, body).is_err());  
    }

}