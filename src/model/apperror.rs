use std::fmt;

/**
 * Represents the type of error that can occur within the application.
 */
#[derive(Debug, Clone)]
pub enum ErrorType {
    InitializationError,
    JwtAuthorizationError,
    NotImplementedError,
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
     * Creates a new ApplicationError.
     *
     * #Arguments
     * `error_type`: The type of error.
     * `message`: A description of the error.
     */
    pub fn new(error_type: ErrorType, message: String) -> Self {
        ApplicationError { error_type: error_type, message: message }
    }
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
