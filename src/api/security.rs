use std::str::FromStr;

use actix_web::{FromRequest, HttpRequest};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::model::apperror::{ApplicationError, ErrorType};

#[derive(Debug, Deserialize)]
struct Claim {
    sub: Option<String>,
    name: Option<String>,
    admin: Option<bool>,
    iat: Option<usize>,
    exp: Option<usize>,
}

/**
 * JWT Security Service for handling JWT authentication.
 */
#[derive(Clone)]
pub struct JwtSecurityService {
    /**
     * The decoding key used to verify JWT tokens.
     */
    decoding_key: DecodingKey,
    /**
     * The validation rules for JWT tokens.
     */
    validation: Validation,
}

impl JwtSecurityService {
    /**
     * Creates a new instance of JwtSecurityService.
     *
     * # Arguments
     * `public_key`: The public key used to decode JWT tokens.
     * `algorithm`: The algorithm used for JWT token validation.
     *
     * # Returns
     * A Result containing the JwtSecurityService or an ApplicationError if initialization fails.
     */
    pub fn new(public_key: &str, algorithm: &str) -> Result<Self, ApplicationError> {
        let algorithm = Algorithm::from_str(algorithm).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Invalid algorithm: {err}")))?;
        let decoding_key = match algorithm {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => DecodingKey::from_rsa_pem(public_key.as_bytes()).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to create decoding key: {err}")))?,
            Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(public_key.as_bytes()).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to create decoding key: {err}")))?,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => DecodingKey::from_secret(public_key.as_bytes()),
            Algorithm::EdDSA => DecodingKey::from_ed_pem(public_key.as_bytes()).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to create decoding key: {err}")))?,
            _ => return Err(ApplicationError::new(ErrorType::Initialization, "Unsupported algorithm".to_string())),
        };
        let validation = Validation::new(algorithm);
        Ok(JwtSecurityService { decoding_key, validation })
    }

    /**
     * Validates the JWT token from the HTTP request.
     *
     * # Arguments
     * `http_request`: The HTTP request containing the JWT token in the Authorization header.
     *
     * # Returns
     * A Result indicating success or an ApplicationError if validation fails.
     */
    pub fn validate(&self, http_request: &HttpRequest) -> Result<(), ApplicationError> {
        let credentials = BearerAuth::from_request(http_request, &mut actix_web::dev::Payload::None).into_inner().ok();
        let Some(credentials) = credentials else {
            return Err(ApplicationError::new(ErrorType::JwtAuthorization, "Unauthorized".to_string()));
        };
        let _token_data = match jsonwebtoken::decode::<Claim>(credentials.token(), &self.decoding_key, &self.validation) {
            Ok(token_data) => token_data,
            Err(err) => {
                eprintln!("JWT validation error: {err}");
                return Err(ApplicationError::new(ErrorType::JwtAuthorization, "Unauthorized".to_string()));
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use actix_web::test::TestRequest;

    use super::*;

    #[test]
    fn test_jwt_security_service_initialization_success() {
        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----";
        let algorithm = "RS256";
        let jwt_service = JwtSecurityService::new(public_key, algorithm);
        assert!(jwt_service.is_ok());
    }

    #[test]
    fn test_jwt_security_service_initialization_invalid_algorithm() {
        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----";
        let algorithm = "XX256";
        let jwt_service = JwtSecurityService::new(public_key, algorithm);
        assert!(jwt_service.is_err());
    }

    #[test]
    fn test_jwt_security_service_initialization_invalid_public_key() {
        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            mwIDAQAB
            -----END PUBLIC KEY-----";
        let algorithm = "RS256";
        let jwt_service = JwtSecurityService::new(public_key, algorithm);
        assert!(jwt_service.is_err());
    }

    #[test]
    fn test_jwt_security_service_validator_success() {
        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----";
        let algorithm = "RS256";
        let jwt_service: JwtSecurityService = JwtSecurityService::new(public_key, algorithm).unwrap();
        let req = TestRequest::with_uri("/api?id=4&name=foo").insert_header(("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc1Mjc4ODMwNCwiZXhwIjoxODkwMDAwMDAwfQ.DgESoJVdXpf8x7R1E1xEFvvskdxPkp6Y1_88-_gzulif179nDiAb2atvAVrfNnTJBZCAbQrXchx_3LB_d0wW0xpLERdInklwl41tH3wJHmYIXiQur1xOD335qPFyT5cANvNQGBSSHNAmy1FCYJWCObxxRPDDa9okY-KZgdigb0-v9e-XveoklTLe_fGbZzBtqqgmfG1HHI_CUDVwn32jRERqatBvpIsYjqwsc-YQPhr6ys7h1BqbMY3FmgQ0CB2Vq48nqbBGCSihEEybfbCFVm_g1WBugNova33byKo8dO9HpLzAqwYF1en0pnGqWyChQhzHU9bKzKF1KQgVcF7dmw")).to_http_request();
        assert!(jwt_service.validate(&req).is_ok());
    }

    #[test]
    fn test_jwt_security_service_validator_failure() {
        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----";
        let algorithm = "RS256";
        let jwt_service: JwtSecurityService = JwtSecurityService::new(public_key, algorithm).unwrap();
        let req = TestRequest::with_uri("/api?id=4&name=foo").to_http_request();
        assert!(jwt_service.validate(&req).is_err());
    }
}
