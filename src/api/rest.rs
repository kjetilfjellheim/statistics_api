use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;

use crate::model::apperror::{ApplicationError, ErrorType};

/**
 * Custom error response for the application.
 */
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /**
     * The error code associated with the error type.
     */
    pub code: u16,
    /**
     * A human-readable message describing the error.
     */
    pub message: String,
}

impl ResponseError for ApplicationError {
    /**
     * Generates an error response for the application error.
     */
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse { code: get_error_code(&self.error_type), message: self.message.clone() };
        HttpResponse::build(get_statuscode(&self.error_type.clone())).json(&error_response)
    }
}

/**
* Maps application errors to HTTP status codes.
*
* # Arguments
* `application_error`: The type of error that occurred.
*
* # Returns
* The corresponding HTTP status code.
*/
fn get_statuscode(application_error: &ErrorType) -> StatusCode {
    match application_error {
        ErrorType::JwtAuthorizationError => StatusCode::UNAUTHORIZED,
        ErrorType::InitializationError => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorType::NotImplementedError => StatusCode::NOT_IMPLEMENTED,
    }
}

/**
 * Maps application errors to error codes.
 *
 * # Arguments
 * `application_error`: The type of error that occurred.
 *
 * # Returns
 * The corresponding error code.
 */
fn get_error_code(application_error: &ErrorType) -> u16 {
    match application_error {
        ErrorType::JwtAuthorizationError => 1000,
        ErrorType::InitializationError => 1001,
        ErrorType::NotImplementedError => 1002,
    }
}
