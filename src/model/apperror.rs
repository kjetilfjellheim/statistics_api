use std::fmt;

/**
 * Represents the type of error that can occur within the application.
 */
#[derive(Debug, Clone)]
pub enum ErrorType {
    Initialization,
    JwtAuthorization,
    DatabaseError,
    NotFound,
    Application,
    ConstraintViolation,
    Validation,
    DigestVerification,
    SignatureVerification,
}

/**
 * Represents an error that occurs within the application.
 */
#[derive(Debug, Clone)]
pub struct ApplicationError {
    /**
     * Error type.
     */
    pub error_type: ErrorType,
    /**
     * Error message describing problem.
     */
    pub message: String,
}

impl ApplicationError {
    /**
     * Creates a new `ApplicationError`.
     *
     * #Arguments
     * `error_type`: The type of error.
     * `message`: A description of the error.
     */
    pub fn new(error_type: ErrorType, message: String) -> Self {
        ApplicationError { error_type, message }
    }
}

/**
 * Implements the Display trait for `ApplicationError`.
 *
 * This allows `ApplicationError` to be formatted as a string to be logged.
 */
impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Application error {}", self.message)
    }
}

#[cfg(test)]
mod test {
    
use super::*;

    #[test]
    fn test_application_error_display() {
        let error = ApplicationError::new(ErrorType::NotFound, "Resource not found".to_string());
        assert_eq!(format!("{}", error), "Application error Resource not found");
    }

    #[test]
    fn test_application_error_debug() {
        let error = ApplicationError::new(ErrorType::DatabaseError, "Database connection failed".to_string());
        assert_eq!(format!("{:?}", error), "ApplicationError { error_type: DatabaseError, message: \"Database connection failed\" }");
    }

}