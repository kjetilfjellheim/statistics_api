use std::collections::{HashMap, HashSet};

use clap::{Parser, command};
use serde::{Deserialize, Serialize};

use crate::api::httpsignatures::VerificationRequirement;

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
     * Logging configuration for the application.
     */
    pub logging: LoggingConfig,
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

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /**
     * Whether to log the target of the log message.
     */
    pub target: bool,
    /**
     * Whether to log thread IDs .
     */
    pub thread_ids: bool,
    /**
     * Whether to log thread names.
     */
    pub thread_names: bool,
    /**
     * Whether to log line numbers.
     */
    pub line_number: bool,
    /**
     * Whether to log the log level.
     */
    pub level: bool,
    /**
     * Whether to use ANSI colors in logs.
     */
    pub ansi: bool,
    /**
     * Whether to log file.
     */
    pub file: bool,
    /**
     * Path to the log file.
     */
    pub logfile: String,
    /**
     * Additional directives for logging configuration.
     */
    pub directives: Vec<String>,
}

impl LoggingConfig {
    #[allow(dead_code)]
    pub fn default() -> Self {
        LoggingConfig { target: true, thread_ids: true, thread_names: true, line_number: true, level: true, ansi: true, file: true, logfile: "/tmp/statistics_api.log".to_string(), directives: vec![] }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Database {
    /**
     * Type of the database (e.g., `PostgreSQL`).
     */
    pub db_type: DatabaseType,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DatabaseType {
    /**
     * `PostgreSQL` database type.
     */
    #[serde(rename_all = "camelCase")]
    Postgresql { connection_string: String, max_connections: u32, min_connections: u32, acquire_timeout: u64, acquire_slow_threshold: u64, idle_timeout: u64, max_lifetime: u64 },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSecurity {
    /**
     * Path to the public key files used for verifying HTTP signatures.
     * Key is the keyid.
     */
    pub secrets: HashMap<String, SecretType>,
    /**
     * Input security configuration.
     */
    pub incoming_verification_requirements: HashSet<VerificationRequirement>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum SecretType {
    /**
     * Public key file.
     */
    PublicKeyFile { path: String },
    /**
     * Shared secret for hmac.
     */
    SharedSecret { secret: String },
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
    fn test_config_serialization_http_signatures() {
        let http_signatures = AppSecurity {
            secrets: HashMap::from([
                ("key1".to_string(), SecretType::PublicKeyFile { path: "./test_config/public_keys/public_key1.pem".to_string() }),
                ("key2".to_string(), SecretType::PublicKeyFile { path: "./test_config/public_keys/public_key2.pem".to_string() }),
                ("key3".to_string(), SecretType::SharedSecret { secret: "test".to_string() }),
            ]),
            incoming_verification_requirements: HashSet::from([
                VerificationRequirement::HeaderRequired { name: "x-request-ID".to_string() },
                VerificationRequirement::HeaderRequired { name: "x-fd-userid".to_string() },
                VerificationRequirement::HeaderRequiredIfBodyPresent { name: "content-digest".to_string() },
                VerificationRequirement::CreatedRequired,
                VerificationRequirement::ExpiresRequired,
                VerificationRequirement::CheckExpired,
                VerificationRequirement::DerivedRequired { name: "@method".to_string() },
                VerificationRequirement::DerivedRequired { name: "@path".to_string() },
                VerificationRequirement::DerivedRequired { name: "@authority".to_string() },
            ]),
        };

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
            security: http_signatures,
            server: Server { workers: 4, http_port: Some(8080), https_config: None },
        };
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(config.logging.target, deserialized.logging.target);
        assert_eq!(config.logging.thread_ids, deserialized.logging.thread_ids);
        assert_eq!(config.logging.line_number, deserialized.logging.line_number);
        assert_eq!(config.logging.level, deserialized.logging.level);
        assert_eq!(config.logging.ansi, deserialized.logging.ansi);
        assert_eq!(config.logging.file, deserialized.logging.file);
        assert_eq!(config.logging.logfile, deserialized.logging.logfile);
        assert_eq!(config.logging.directives, deserialized.logging.directives);
        assert_eq!(config.server.workers, deserialized.server.workers);
        assert_eq!(config.server.http_port, deserialized.server.http_port);
        assert!(deserialized.server.https_config.is_none());
        assert_eq!(deserialized.security.secrets.get("key1").unwrap(), &SecretType::PublicKeyFile { path: "./test_config/public_keys/public_key1.pem".to_string() });
        assert_eq!(deserialized.security.secrets.get("key2").unwrap(), &SecretType::PublicKeyFile { path: "./test_config/public_keys/public_key2.pem".to_string() });
        assert_eq!(deserialized.security.secrets.get("key3").unwrap(), &SecretType::SharedSecret { secret: "test".to_string() });
    }
}
