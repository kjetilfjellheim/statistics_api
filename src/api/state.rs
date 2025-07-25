use crate::{api::security::JwtSecurityService, model::config::Config, service::statistics::StatisticsService};

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
    #[allow(dead_code)]
    pub config: Config,
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
    pub fn new(jwt_service: JwtSecurityService, config: Config, statistics_service: StatisticsService) -> Self {
        AppState { jwt_service, config, statistics_service }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        api::security::JwtSecurityService,
        dao::statistics::StatisticsDao,
        model::config::{AppSecurity, Database, DatabaseType, LoggingConfig, Server},
    };

    #[test]
    fn test_app_state_initialization() {
        let statistics_dao = StatisticsDao::new();
        let statistics_service = StatisticsService::new(statistics_dao, None);

        let public_key = "-----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----"
            .to_string();
        let public_key_file = "/tmp/config/jwt_public_key.pem".to_string();
        let jwt_service = JwtSecurityService::new(&public_key, "RS256").unwrap();
        let config = Config {
            logging: LoggingConfig::default(),
            database: Database {
                db_type: DatabaseType::Postgresql {
                    connection_string: "".to_string(),
                    max_connections: 5,
                    min_connections: 1,
                    acquire_timeout: 30,
                    acquire_slow_threshold: 60,
                    idle_timeout: 300,
                    max_lifetime: 3600,
                },
            },
            security: AppSecurity { jwt_secret: public_key_file, jwt_algorithm: "HS256".to_string() },
            server: Server { workers: 4, http_port: Some(8080), https_config: None },
        };
        AppState::new(jwt_service, config, statistics_service);
    }
}
