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

    /**
     * Path to the log file.
     */
    #[arg(short, long)]
    pub log_file: String,
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
    /**
     * Database configuration for the application.
     */
    pub database: Database,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Database {
    /**
     * Type of the database (e.g., PostgreSQL).
     */
    pub db_type: DatabaseType,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DatabaseType {
    /**
     * PostgreSQL database type.
     */
    #[serde(rename_all = "camelCase")]
    Postgresql { connection_string: String, max_connections: usize, min_connections: usize, acquire_timeout: usize, acquire_slow_threshold: usize, idle_timeout: usize, max_lifetime: usize },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSecurity {
    /**
     * JWT SECRET used for verifying tokens. This can be a public key file or a secret string.
     */
    pub jwt_secret: String,
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
    pub port: u16,
    /**
     * Path to the certificate file.
     */
    pub certificate_file: String,
    /**
     * Path to the private key file.
     */
    pub private_key_file: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
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
            security: AppSecurity { jwt_secret: "/tmp/config/jwt_public_key.pem".to_string(), jwt_algorithm: "RS256".to_string() },
            server: Server { workers: 4, http_port: Some(8080), https_config: None },
        };
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(config.security.jwt_secret, deserialized.security.jwt_secret);
        assert_eq!(config.security.jwt_algorithm, deserialized.security.jwt_algorithm);
        assert_eq!(config.server.workers, deserialized.server.workers);
        assert_eq!(config.server.http_port, deserialized.server.http_port);
        assert!(deserialized.server.https_config.is_none());
    }
}
