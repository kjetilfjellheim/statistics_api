mod api;
mod model;

use crate::api::security::JwtSecurityService;
use crate::model::config::{AppSecurity, ApplicationArguments};

use crate::api::endpoints::{municipalities_add, municipalities_delete, municipalities_list, statistics_add, statistics_delete, statistics_list, value_add, value_delete, value_update, values_list};
use crate::api::state::AppState;
use actix_web::{App, HttpServer, web};
use clap::Parser;

/**
 * Guess, but this might be the main entry point for the application.
 */
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = ApplicationArguments::parse();
    let config = get_config(&args.config_file)?;
    let jwt_service = get_jwt_service(&config.security)?;
    let state = web::Data::new(AppState::new(jwt_service.clone(), config.clone()));

    let server_init = HttpServer::new(move || {
        App::new()
            .wrap(actix_web::middleware::Logger::default())
            .app_data(state.clone())
            .service(statistics_list)
            .service(statistics_add)
            .service(statistics_delete)
            .service(municipalities_list)
            .service(municipalities_add)
            .service(municipalities_delete)
            .service(values_list)
            .service(value_add)
            .service(value_delete)
            .service(value_update)
    });

    let server_init = if let Some(http_port) = &config.server.http_port { server_init.bind(("127.0.0.1", *http_port))? } else { server_init };
    let server_init = if let Some(_https_config) = &config.server.https_config {
        //TODO: Implement HTTPS support
        server_init
    } else {
        server_init
    };

    server_init.workers(config.server.workers).run().await
}

/**
 * Reads the configuration from the specified file.
 *
 * #Arguments
 * `config_file`: The path to the configuration file.
 *
 * #Returns
 * A `Result` containing the parsed `Config` or an `std::io::Error` if reading or parsing fails.
*/
fn get_config(config_file: &str) -> Result<model::config::Config, std::io::Error> {
    let config_str: String = std::fs::read_to_string(&config_file).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to read config file: {}", err)))?;
    let config: model::config::Config = toml::from_str(&config_str).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to parse config file: {}", err)))?;
    Ok(config)
}

/**
 * Initializes the JWT security service using the provided configuration.
 *
 * #Arguments
 * `jwt_config`: The JWT security configuration containing the public key and algorithm.
 *
 * #Returns
 * A `Result` containing the initialized `JwtSecurityService` or an `std::io::Error` if initialization fails.
 */
fn get_jwt_service(jwt_config: &AppSecurity) -> Result<JwtSecurityService, std::io::Error> {
    let pub_key = std::fs::read_to_string(&jwt_config.jwt_public_key).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to read public key file: {}", err)))?;
    JwtSecurityService::new(&pub_key, &jwt_config.jwt_algorithm).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create JWT service: {}", err.message)))
}
