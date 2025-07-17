use clap::{Parser, command};
use serde::{Deserialize, Serialize};

/**
 * Command-line arguments for the application.
 */
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct ApplicationArguments {
    /**
     * Path to the configuration file.
     */
    #[arg(short, long)]
    pub config_file: String,
}

/**
 * Represents the configuration for the application.
 */
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /**
     * Security configuration for the application.
     */
    pub security: AppSecurity,
    /**
     * Server configuration for the application.
     */
    pub server: Server,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSecurity {
    /**
     * JWT PUBLIC key used for verifying tokens.
     */
    pub jwt_public_key: String,
    /**
     * JWT algorithm used for signing tokens.
     */
    pub jwt_algorithm: String,
}

/**
 * Represents the server configuration for the application.
 */
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    /**
     * Number of worker threads for the server.
     */
    pub workers: usize,
    /**
     * HTTP port for the server.
     */
    pub http_port: Option<u16>,
    /**
     * HTTPS configuration for the server.
     */ 
    pub https_config: Option<HttpsConfig>,
}

/**
 * Represents the HTTPS configuration for the server.
 */
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpsConfig {
    /**
     * Port for the HTTPS server.
     */
    pubport: u16,
    /**
     * Path to the certificate file.
     */
    pub certificate: String,
    /**
     * Path to the private key file.
     */
    pub private_key: String,
}
