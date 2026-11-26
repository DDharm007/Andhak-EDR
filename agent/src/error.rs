use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TOML parse error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("TOML serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("SQLite spool error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Authentication or enrollment error: {0}")]
    Auth(String),

    #[error("Backend rejected request ({status}): {body}")]
    Backend { status: u16, body: String },

    #[error("Collector error: {0}")]
    Collector(String),
}
