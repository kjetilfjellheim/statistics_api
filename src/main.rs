mod api;
mod dao;
mod model;
mod service;

use std::fs::File;
use std::io::BufReader;

use crate::api::security::JwtSecurityService;
use crate::dao::statistics::StatisticsDao;
use crate::model::apperror::{ApplicationError, ErrorType};
use crate::model::config::{AppSecurity, ApplicationArguments, DatabaseType, HttpsConfig};

use crate::api::endpoints::{municipalities_add, municipalities_delete, municipalities_list, statistics_add, statistics_delete, statistics_list, value_add, value_delete, value_update, values_list};
use crate::api::state::AppState;
use crate::service::statistics::StatisticsService;
use actix_web::{App, HttpServer, web};
use actix_web_prom::PrometheusMetricsBuilder;
use clap::Parser;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sqlx::{Pool, Postgres, pool};

/**
 * Guess, but this might be the main entry point for the application.
 */
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = ApplicationArguments::parse();

    log4rs::init_file(args.log_file, Default::default()).map_err(|err| std::io::Error::other(format!("Failed to initialize logging: {err}")))?;

    let config = get_config(&args.config_file)?;

    let connection_pool: Pool<Postgres> = match config.clone().database.db_type {
        DatabaseType::Postgresql { connection_string, max_connections, min_connections, acquire_timeout, acquire_slow_threshold, idle_timeout, max_lifetime } => pool::PoolOptions::new()
            .max_connections(max_connections as u32)
            .min_connections(min_connections as u32)
            .acquire_timeout(std::time::Duration::from_millis(acquire_timeout as u64))
            .acquire_slow_threshold(std::time::Duration::from_millis(acquire_slow_threshold as u64))
            .idle_timeout(std::time::Duration::from_millis(idle_timeout as u64))
            .max_lifetime(std::time::Duration::from_millis(max_lifetime as u64))
            .connect(connection_string.as_str())
            .await
            .map_err(|err| std::io::Error::other(format!("Failed to create database pool: {err}")))?,
    };

    let jwt_service = get_jwt_service(&config.security)?;

    let statistics_dao = StatisticsDao::new();
    let statistics_service = StatisticsService::new(statistics_dao, Some(connection_pool));

    let state = web::Data::new(AppState::new(jwt_service.clone(), config.clone(), statistics_service));

    let prometheus = PrometheusMetricsBuilder::new("")
        .endpoint("/metrics/prometheus")
        .mask_unmatched_patterns("UNKNOWN")
        .build()
        .map_err(|err| std::io::Error::other(format!("Failed to create Prometheus metrics: {err}")))?;

    let server_init = HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
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
        let ssl_builder = ssl_builder(_https_config).await.map_err(|err| std::io::Error::other(format!("Failed to create SSL/TLS configuration: {err}")))?;
        server_init.bind_rustls_0_23("127.0.0.1:".to_string() + &_https_config.port.to_string(), ssl_builder).map_err(|err| std::io::Error::other(format!("Failed to bind HTTPS server: {err}")))?
    } else {
        server_init
    };

    server_init.workers(config.server.workers).run().await
}

/**
 * Initializes the SSL/TLS configuration for the server.
 *
 * #Arguments
 * `https_config`: The HTTPS configuration containing the certificate and private key files.
 *
 * #Returns
 * A `Result` containing the initialized `ServerConfig` or an `ApplicationError` if initialization fails.
 */
async fn ssl_builder(https_config: &HttpsConfig) -> Result<ServerConfig, ApplicationError> {
    let config_builder = ServerConfig::builder_with_protocol_versions(&get_protocol_versions());
    let cert_file =
        &mut BufReader::new(File::open(https_config.clone().certificate_file).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to read certificate file: {err}")))?);
    let key_file =
        &mut BufReader::new(File::open(https_config.clone().private_key_file).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to read private key file: {err}")))?);
    let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to convert certificate to der: {err}")))?;
    let mut keys = pkcs8_private_keys(key_file)
        .map(|key| key.map(PrivateKeyDer::Pkcs8))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to convert private key to der: {err}")))?;
    let config = config_builder
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to create server config: {err}")))?;
    Ok(config)
}

/**
 * Returns the supported TLS protocol versions.
 *
 * #Returns
 * A vector of supported protocol versions.
 */
fn get_protocol_versions() -> Vec<&'static SupportedProtocolVersion> {
    vec![&rustls::version::TLS13]
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
    let config_str: String = std::fs::read_to_string(config_file).map_err(|err| std::io::Error::other(format!("Failed to read config file: {err}")))?;
    let config: model::config::Config = toml::from_str(&config_str).map_err(|err| std::io::Error::other(format!("Failed to parse config file: {err}")))?;
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
    let pub_key = std::fs::read_to_string(&jwt_config.jwt_secret).map_err(|err| std::io::Error::other(format!("Failed to read public key file: {err}")))?;
    JwtSecurityService::new(&pub_key, &jwt_config.jwt_algorithm).map_err(|err| std::io::Error::other(format!("Failed to create JWT service: {err}")))
}
