mod api;
mod dao;
mod model;
mod service;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::api::middleware;
use crate::api::security::JwtSecurityService;
use crate::dao::statistics::StatisticsDao;
use crate::model::apperror::{ApplicationError, ErrorType};
use crate::model::config::{AppSecurity, ApplicationArguments, DatabaseType, HttpsConfig};

use crate::api::endpoints::{municipalities_add, municipalities_delete, municipalities_list, statistics_add, statistics_delete, statistics_list, value_add, value_delete, value_update, values_list};
use crate::api::state::AppState;
use crate::service::statistics::StatisticsService;
use actix_web::middleware::{from_fn, Logger};
use actix_web::{App, HttpServer, web};
use actix_web_prom::{PrometheusMetrics, PrometheusMetricsBuilder};
use clap::Parser;
use prometheus::IntGauge;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sqlx::{Pool, Postgres, pool};
use tracing_subscriber::EnvFilter;

/**
 * Guess, but this might be the main entry point for the application.
 */
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = ApplicationArguments::parse();

    let config = get_config(&args.config_file)?;

    let mut filter = EnvFilter::try_from_default_env().map_err(|err| std::io::Error::other(format!("Failed to create logging filter: {err}")))?;
    for directive in &config.logging.directives {
        filter = filter.add_directive(directive.parse().map_err(|err| std::io::Error::other(format!("Failed to parse logging directive: {err}")))?);
    }
    let log_file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&config.logging.logfile)
        .map_err(|err| std::io::Error::other(format!("Failed to open log file: {err}")))?;

    // Initialize logging
    tracing_subscriber::fmt()
        .compact()
        .with_writer(log_file)
        .with_env_filter(filter)
        .with_target(config.logging.target)
        .with_thread_ids(config.logging.thread_ids)
        .with_thread_names(config.logging.thread_names)
        .with_line_number(config.logging.line_number)
        .with_level(config.logging.level)
        .with_ansi(config.logging.ansi)
        .with_file(config.logging.file)
        .init();

    let connection_pool: Pool<Postgres> = match config.clone().database.db_type {
        DatabaseType::Postgresql { connection_string, max_connections, min_connections, acquire_timeout, acquire_slow_threshold, idle_timeout, max_lifetime } => pool::PoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .acquire_timeout(std::time::Duration::from_millis(acquire_timeout))
            .acquire_slow_threshold(std::time::Duration::from_millis(acquire_slow_threshold))
            .idle_timeout(std::time::Duration::from_millis(idle_timeout))
            .max_lifetime(std::time::Duration::from_millis(max_lifetime))
            .connect(connection_string.as_str())
            .await
            .map_err(|err| std::io::Error::other(format!("Failed to create database pool: {err}")))?,
    };
    let connection_pool = Arc::new(connection_pool);

    let jwt_service = get_jwt_service(&config.security)?;

    let statistics_dao = StatisticsDao::new();
    let statistics_service = StatisticsService::new(statistics_dao, connection_pool.clone());

    let state = web::Data::new(AppState::new(jwt_service.clone(),statistics_service));

    let prometheus = PrometheusMetricsBuilder::new("")
        .endpoint("/metrics/prometheus")
        .mask_unmatched_patterns("UNKNOWN")
        .build()
        .map_err(|err| std::io::Error::other(format!("Failed to create Prometheus metrics: {err}")))?;

    // Initialize custom metrics
    let max_connections_gauge = IntGauge::new("max_connections", "Connection pool maximum")
        .map_err(|err| std::io::Error::other(format!("Failed to create max_connections gauge: {err}")))?;
    let min_connections_gauge = IntGauge::new("min_connections", "Connection pool minimum")
        .map_err(|err| std::io::Error::other(format!("Failed to create min_connections gauge: {err}")))?;
    let active_connections_gauge = IntGauge::new("active_connections", "Connection pool active")
        .map_err(|err| std::io::Error::other(format!("Failed to create active_connections gauge: {err}")))?;
    let idle_connections_gauge = IntGauge::new("idle_connections", "Connection pool idle")
        .map_err(|err| std::io::Error::other(format!("Failed to create idle_connections gauge: {err}")))?;
    //Register custom prometheus metrics
    register_promethius_metrics(&prometheus, &max_connections_gauge)?;
    register_promethius_metrics(&prometheus, &min_connections_gauge)?;
    register_promethius_metrics(&prometheus, &active_connections_gauge)?;
    register_promethius_metrics(&prometheus, &idle_connections_gauge)?;

    gather_db_metrics(max_connections_gauge, min_connections_gauge, active_connections_gauge, idle_connections_gauge, connection_pool);

    let server_init = HttpServer::new(move || {
        App::new()
            .wrap(prometheus.clone())
            .wrap(from_fn(middleware::timing_middleware))
            .wrap(from_fn(middleware::digest_verification_middleware))
            .wrap(Logger::new(
                "%a %r %s %b %{Referer}i %{User-Agent}i %{X-Request-id}i %Dms"
            ))
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
    let server_init = if let Some(https_config) = &config.server.https_config {
        let ssl_builder = ssl_builder(https_config).map_err(|err| std::io::Error::other(format!("Failed to create SSL/TLS configuration: {err}")))?;
        server_init.bind_rustls_0_23("127.0.0.1:".to_string() + &https_config.port.to_string(), ssl_builder).map_err(|err| std::io::Error::other(format!("Failed to bind HTTPS server: {err}")))?
    } else {
        server_init
    };

    server_init.workers(config.server.workers).run().await
}

/**
 * Registers custom Prometheus metrics.
 *
 * #Arguments
 * `prometheus_metrics`: The Prometheus metrics instance to register the gauge with.
 * `gauge`: The gauge to register.
 */
fn register_promethius_metrics(prometheus_metrics: &PrometheusMetrics, gauge: &IntGauge) -> Result<(), std::io::Error> {
    prometheus_metrics
        .registry
        .register(Box::new(gauge.clone()))
        .map_err(|err| std::io::Error::other(format!("Failed to register Prometheus gauge: {err}")))?;
    Ok(())
}

/**
 * Gathers database metrics in a separate thread.
 *
 * #Arguments
 * `max_connections_gauge`: Gauge for maximum connections.
 * `min_connections_gauge`: Gauge for minimum connections.
 * `active_connections_gauge`: Gauge for active connections.
 * `idle_connections_gauge`: Gauge for idle connections.
 * `connection_pool`: The connection pool to gather metrics from.
 */
fn gather_db_metrics(max_connections_gauge: IntGauge, min_connections_gauge: IntGauge, active_connections_gauge: IntGauge, idle_connections_gauge: IntGauge, connection_pool: Arc<Pool<Postgres>>) {
    thread::spawn(move || loop {
        max_connections_gauge.set(i64::from(connection_pool.options().get_max_connections()));
        min_connections_gauge.set(i64::from(connection_pool.options().get_min_connections()));
        active_connections_gauge.set(i64::from(connection_pool.size()));
        #[allow(clippy::cast_possible_wrap)]
        idle_connections_gauge.set(connection_pool.num_idle() as i64);
        thread::sleep(Duration::from_secs(1));
    });
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
fn ssl_builder(https_config: &HttpsConfig) -> Result<ServerConfig, ApplicationError> {
    let config_builder = ServerConfig::builder_with_protocol_versions(&get_protocol_versions());
    let cert_file =
        &mut std::io::BufReader::new(std::fs::File::open(https_config.clone().certificate_file).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to read certificate file: {err}")))?);
    let key_file =
        &mut std::io::BufReader::new(std::fs::File::open(https_config.clone().private_key_file).map_err(|err| ApplicationError::new(ErrorType::Initialization, format!("Failed to read private key file: {err}")))?);
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
