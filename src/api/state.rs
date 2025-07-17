use crate::{api::security::JwtSecurityService, model::config::Config};

/**
* Represents the application state shared across the Actix web application.
*/
pub struct AppState {
    /**
     * The JWT security service for handling authentication and authorization.
     */
    pub jwt_service: JwtSecurityService,
    /**
     * The application configuration.
     */
    pub config: Config,
}

impl AppState {
    pub fn new(jwt_service: JwtSecurityService, config: Config) -> Self {
        AppState { jwt_service, config }
    }
}
