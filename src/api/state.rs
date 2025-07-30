use crate::{api::security::JwtSecurityService, service::statistics::StatisticsService};

/**
* Represents the application state shared across the Actix web application.
*/
pub struct AppState {
    /**
     * The JWT security service for handling authentication and authorization.
     */
    pub jwt_service: JwtSecurityService,
    /**
     * The statistics service for handling statistics-related operations.
     */
    pub statistics_service: StatisticsService,
}

/**
 * Creates a new instance of `AppState`.
 *
 * # Arguments
 * `jwt_service`: The JWT security service for handling authentication and authorization.
 * `config`: The application configuration.
 * `statistics_service`: The statistics service for handling statistics-related operations.
 */
impl AppState {
    pub fn new(jwt_service: JwtSecurityService, statistics_service: StatisticsService) -> Self {
        AppState { jwt_service, statistics_service }
    }
}
