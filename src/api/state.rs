use crate::{api::httpsignatures::HttpSignaturesService, service::statistics::StatisticsService};

/**
* Represents the application state shared across the Actix web application.
*/
pub struct AppState {
    /**
     * The security service for handling authentication and authorization.
     */
    pub security_service: HttpSignaturesService,
    /**
     * The statistics service for handling statistics-related operations.
     */
    pub statistics_service: StatisticsService,
}

/**
 * Creates a new instance of `AppState`.
 *
 * # Arguments
 * `security_service`: The security service for handling authentication and authorization.
 * `config`: The application configuration.
 * `statistics_service`: The statistics service for handling statistics-related operations.
 */
impl AppState {
    pub fn new(security_service: HttpSignaturesService, statistics_service: StatisticsService) -> Self {
        AppState { security_service, statistics_service }
    }
}
