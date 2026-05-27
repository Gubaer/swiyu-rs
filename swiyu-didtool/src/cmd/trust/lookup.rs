use swiyu_core::truststatement::TrustStatement;

use crate::cmd::{iso8601, resolve_did};
use crate::keystore::KeyStore;

use super::TrustError;

// Re-export the shared error type as `LookupError` for clarity at call sites.
pub use super::TrustError as LookupError;

#[allow(dead_code)] // raw is referenced via field access only by way of args
pub struct LookupArgs {
    pub did: String,
    pub trust_registry_url: Option<String>,
    pub raw: bool,
}

#[derive(Debug)]
pub enum LookupOutcome {
    Found,
    NoStatements,
}

pub fn cmd_lookup(store: &KeyStore, args: LookupArgs) -> Result<LookupOutcome, LookupError> {
    let base_url = args
        .trust_registry_url
        .ok_or(TrustError::TrustRegistryUrlMissing)?;
    let did = resolve_did(store, &args.did)?;
    let did_str = did.to_string();

    let array = super::fetch_statements(&base_url, &did)?;
    process_statements(&did_str, array, args.raw)
}

fn process_statements(
    did: &str,
    array: Vec<String>,
    raw: bool,
) -> Result<LookupOutcome, LookupError> {
    if array.is_empty() {
        eprintln!("no trust statements found for {did}");
        return Ok(LookupOutcome::NoStatements);
    }

    if raw {
        let pretty =
            serde_json::to_string_pretty(&array).expect("array of strings is serialisable");
        println!("{pretty}");
        return Ok(LookupOutcome::Found);
    }

    let mut statements = Vec::with_capacity(array.len());
    for (i, jwt) in array.iter().enumerate() {
        let s = TrustStatement::try_from_jwt(jwt)
            .map_err(|source| TrustError::Statement { n: i + 1, source })?;
        statements.push(s);
    }
    statements.sort_by_key(|s| std::cmp::Reverse(s.iat));

    println!("Trust statements for {did}");
    for (i, s) in statements.iter().enumerate() {
        println!();
        print_statement(i + 1, s);
    }

    Ok(LookupOutcome::Found)
}

fn print_statement(n: usize, s: &TrustStatement) {
    println!("#{n}  {}", s.vct);
    println!("  issuer:            {}", s.iss);
    println!("  iat (issued at):   {}", iso8601(s.iat));
    if let Some(t) = s.nbf {
        println!("  nbf (not before):  {}", iso8601(t));
    }
    if let Some(t) = s.exp {
        println!("  exp (expires):     {}", iso8601(t));
    }
    if s.entity_name.is_empty() {
        println!("  entity name:       (none)");
    } else {
        let mut first = true;
        for (lang, name) in &s.entity_name {
            if first {
                println!("  entity name:       {lang}: {name}");
                first = false;
            } else {
                println!("                     {lang}: {name}");
            }
        }
    }
    println!(
        "  state actor:       {}",
        match s.is_state_actor {
            Some(true) => "yes",
            Some(false) => "no",
            None => "(undisclosed)",
        }
    );
    if let Some(st) = &s.status {
        println!("  status:            {} idx={}", st.type_(), st.idx());
        println!("                     {}", st.uri());
    }
}

#[cfg(test)]
mod tests {
    use super::super::{build_jwt, is_state_actor_disclosure};
    use super::*;
    use serde_json::json;

    #[test]
    fn process_statements_empty_returns_no_statements() {
        let outcome = process_statements("did:tdw:abc", Vec::new(), false).unwrap();
        assert!(matches!(outcome, LookupOutcome::NoStatements));
    }

    #[test]
    fn process_statements_one_statement_returns_found() {
        let jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(true)]);
        let outcome = process_statements("did:tdw:abc", vec![jwt], false).unwrap();
        assert!(matches!(outcome, LookupOutcome::Found));
    }
}
