use std::env;
use std::io;

use chrono::Duration;
use clap::{ArgGroup, Args, Parser, Subcommand};
use secrecy::SecretString;
use sqlx::PgPool;
use swiyu_issuer::cli;
use swiyu_issuer::domain::TenantId;
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
    /// Write a fresh OAuth2 refresh token (the "renewal token" from
    /// the ePortal) into the named tenant's row. Idempotent.
    ImportOauthRefreshToken(ImportOauthRefreshTokenArgs),
    /// Write the OAuth2 `client_id` + `client_secret` (ePortal
    /// "customer key" / "customer secret") into the named tenant's
    /// row. Both columns are written atomically; partial updates
    /// would leave the row unable to mint tokens.
    SetOauthCredentials(SetOauthCredentialsArgs),
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("token_source")
        .required(true)
        .args(["token", "token_stdin"])
))]
struct ImportOauthRefreshTokenArgs {
    /// Bare base58 tenant id (no `tenant_` prefix).
    #[arg(long)]
    tenant: String,
    /// The new refresh token value. Mutually exclusive with --token-stdin.
    #[arg(long)]
    token: Option<String>,
    /// Read the new refresh token from stdin instead of the command line.
    /// Avoids leaking the secret into shell history. Mutually exclusive
    /// with --token.
    #[arg(long)]
    token_stdin: bool,
    /// Skip the write if `oauth_refresh_token` is already populated.
    /// Used by the dev-loop auto-seed so a token the runtime has
    /// rotated is never clobbered. The operator path omits this flag
    /// and overwrites unconditionally.
    #[arg(long)]
    only_if_empty: bool,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("client_secret_source")
        .required(true)
        .args(["client_secret", "client_secret_stdin"])
))]
struct SetOauthCredentialsArgs {
    /// Bare base58 tenant id (no `tenant_` prefix).
    #[arg(long)]
    tenant: String,
    /// OAuth2 client id (ePortal: "customer key").
    #[arg(long)]
    client_id: String,
    /// OAuth2 client secret. Mutually exclusive with
    /// --client-secret-stdin.
    #[arg(long)]
    client_secret: Option<String>,
    /// Read the OAuth2 client secret from stdin instead of the command
    /// line. Avoids leaking the secret into shell history. Mutually
    /// exclusive with --client-secret.
    #[arg(long)]
    client_secret_stdin: bool,
    /// Skip the write if `oauth_client_id` and `oauth_client_secret`
    /// are both already populated. Used by the dev-loop auto-seed so
    /// previously written credentials are never clobbered. The
    /// operator path (credential rotation at the ePortal) omits this
    /// flag and overwrites unconditionally.
    #[arg(long)]
    only_if_empty: bool,
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
            TenantCommand::ImportOauthRefreshToken(args) => import_oauth_refresh_token(args).await,
            TenantCommand::SetOauthCredentials(args) => set_oauth_credentials(args).await,
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
    let expires_at = expires_in.map(|d| chrono::Utc::now() + d);

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let pool: PgPool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let minted = cli::tenant::api_token::mint(&pool, tenant_id, name, expires_at).await?;

    // Print the bare wire form on stdout exactly once. The reminder
    // goes to stderr so a `| jq .` or other piping does not lose it.
    println!("{}", minted.secret.as_wire());
    eprintln!(
        "save this token now; only its hash is persisted. id={} name={}",
        minted.token.id, minted.token.name
    );

    Ok(())
}

async fn import_oauth_refresh_token(
    args: ImportOauthRefreshTokenArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::from_bare(&args.tenant)
        .map_err(|err| format!("--tenant is not a valid bare tenant id: {err}"))?;

    let raw_token = match (args.token, args.token_stdin) {
        (Some(value), false) => value,
        (None, true) => {
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
            buf.trim().to_string()
        }
        // clap's ArgGroup enforces exactly one of --token / --token-stdin.
        _ => unreachable!("ArgGroup invariant: token_source is required and single-pick"),
    };
    if raw_token.is_empty() {
        return Err("refresh token is empty".into());
    }
    let token = SecretString::from(raw_token);

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let pool: PgPool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let outcome =
        cli::tenant::import_oauth_refresh_token(&pool, &tenant_id, token, args.only_if_empty)
            .await?;

    match outcome {
        cli::tenant::SeedOutcome::Wrote => {
            eprintln!("oauth_refresh_token updated for tenant {}", args.tenant);
        }
        cli::tenant::SeedOutcome::Skipped => {
            eprintln!(
                "oauth_refresh_token already set for tenant {}; skipped (--only-if-empty)",
                args.tenant
            );
        }
    }
    Ok(())
}

async fn set_oauth_credentials(
    args: SetOauthCredentialsArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = TenantId::from_bare(&args.tenant)
        .map_err(|err| format!("--tenant is not a valid bare tenant id: {err}"))?;

    let raw_secret = match (args.client_secret, args.client_secret_stdin) {
        (Some(value), false) => value,
        (None, true) => {
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
            buf.trim().to_string()
        }
        // clap's ArgGroup enforces exactly one of --client-secret /
        // --client-secret-stdin.
        _ => unreachable!("ArgGroup invariant: client_secret_source is required and single-pick"),
    };
    if args.client_id.is_empty() {
        return Err("--client-id is empty".into());
    }
    if raw_secret.is_empty() {
        return Err("client secret is empty".into());
    }
    let client_secret = SecretString::from(raw_secret);

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let pool: PgPool = persistence::connect(&database_url).await?;
    persistence::run_migrations(&pool).await?;

    let outcome = cli::tenant::set_oauth_credentials(
        &pool,
        &tenant_id,
        args.client_id,
        client_secret,
        args.only_if_empty,
    )
    .await?;

    match outcome {
        cli::tenant::SeedOutcome::Wrote => {
            eprintln!(
                "oauth_client_id and oauth_client_secret updated for tenant {}",
                args.tenant
            );
        }
        cli::tenant::SeedOutcome::Skipped => {
            eprintln!(
                "oauth_client_id and oauth_client_secret already set for tenant {}; skipped (--only-if-empty)",
                args.tenant
            );
        }
    }
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
