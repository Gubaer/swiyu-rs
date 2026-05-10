use std::env;

use chrono::Duration;
use clap::{Parser, Subcommand};
use sqlx::PgPool;
use swiyu_issuer::domain::{ApiToken, ApiTokenSecret, TenantId};
use swiyu_issuer::persistence;

#[derive(Parser, Debug)]
#[command(
    name = "swiyu-issuer-cli",
    about = "Operator CLI for swiyu-issuer. All operations are tenant-scoped."
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand, Debug)]
enum TopCommand {
    /// Tenant-scoped operations.
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TenantCommand {
    /// API tokens scoped to a tenant.
    ApiToken {
        #[command(subcommand)]
        command: ApiTokenCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ApiTokenCommand {
    /// Mint a new API token for the named tenant. Prints the bare wire form
    /// (`tok_…`) once on stdout; only the hash is persisted.
    Mint {
        /// Bare base58 tenant id (no `tenant_` prefix).
        #[arg(long)]
        tenant: String,
        /// Operator-supplied label; surfaces in audit logs once the audit
        /// slice lands.
        #[arg(long)]
        name: String,
        /// Lifetime of the token, e.g. `30d`, `12h`, `90m`. Omit for a
        /// non-expiring token.
        #[arg(long)]
        expires_in: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        TopCommand::Tenant { command } => match command {
            TenantCommand::ApiToken { command } => match command {
                ApiTokenCommand::Mint {
                    tenant,
                    name,
                    expires_in,
                } => mint_token(tenant, name, expires_in.as_deref()).await,
            },
        },
    }
}

async fn mint_token(
    tenant: String,
    name: String,
    expires_in: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::from_bare(&tenant)
        .map_err(|err| format!("--tenant is not a valid bare tenant id: {err}"))?;
    let expires_in = expires_in.map(parse_duration).transpose()?;

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let pool: PgPool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let mut conn = pool.acquire().await?;

    let secret = ApiTokenSecret::generate();
    let expires_at = expires_in.map(|d| chrono::Utc::now() + d);
    let token = ApiToken::new(tenant_id, name, secret.hash(), expires_at);

    persistence::api_tokens::insert(&mut conn, &token).await?;

    // Print the bare wire form on stdout exactly once. The reminder
    // goes to stderr so a `| jq .` or other piping does not lose it.
    println!("{}", secret.as_wire());
    eprintln!(
        "save this token now; only its hash is persisted. id={} name={}",
        token.id, token.name
    );

    Ok(())
}

/// Wraps `humantime::parse_duration` and converts to `chrono::Duration`.
///
/// Accepts any format `humantime` accepts (`30s`, `5m`, `12h`, `30d`,
/// `1h30m`, `1d6h`, …). Zero-length durations are rejected because an
/// already-expired token is never useful.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let std_dur =
        humantime::parse_duration(s).map_err(|err| format!("invalid duration {s:?}: {err}"))?;
    if std_dur.is_zero() {
        return Err(format!("duration must be positive: {s:?}"));
    }
    Duration::from_std(std_dur).map_err(|err| format!("duration out of supported range: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_simple_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::seconds(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::minutes(5));
        assert_eq!(parse_duration("12h").unwrap(), Duration::hours(12));
        assert_eq!(parse_duration("90d").unwrap(), Duration::days(90));
    }

    #[test]
    fn parse_duration_accepts_compound_form() {
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            Duration::hours(1) + Duration::minutes(30)
        );
    }

    #[test]
    fn parse_duration_rejects_zero() {
        assert!(parse_duration("0s").is_err());
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("notaduration").is_err());
    }
}
