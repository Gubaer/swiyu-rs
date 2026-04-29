use tracing::debug;

use crate::cmd::iso8601;
use crate::keystore::KeyStore;

use super::{
    BusinessEntityError, DecodedStatement, FetchOutcome, build_endpoint, decode_statement,
    fetch_text, resolve_did,
};

// Re-export the shared error type as `LookupError` for clarity at call sites.
pub use super::BusinessEntityError as LookupError;

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
        .ok_or(BusinessEntityError::TrustRegistryUrlMissing)?;
    let did = resolve_did(store, &args.did)?;
    let endpoint = build_endpoint(&base_url, &did);
    debug!("GET {endpoint}");

    let did_str = did.to_string();
    let body = match fetch_text(&endpoint)? {
        FetchOutcome::NotFound => {
            eprintln!("no trust statements found for {did_str}");
            return Ok(LookupOutcome::NoStatements);
        }
        FetchOutcome::Ok(body) => body,
    };

    process_body(&did_str, &body, args.raw)
}

fn process_body(did: &str, body: &str, raw: bool) -> Result<LookupOutcome, LookupError> {
    let array: Vec<String> =
        serde_json::from_str(body).map_err(|_| BusinessEntityError::ResponseShape)?;

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
        let s = decode_statement(jwt)
            .map_err(|reason| BusinessEntityError::Statement { n: i + 1, reason })?;
        statements.push(s);
    }
    statements.sort_by(|a, b| b.iat.cmp(&a.iat));

    println!("Trust statements for {did}");
    for (i, s) in statements.iter().enumerate() {
        println!();
        print_statement(i + 1, s);
    }

    Ok(LookupOutcome::Found)
}

fn print_statement(n: usize, s: &DecodedStatement) {
    println!("#{n}  {}", s.vct);
    println!("  issuer:       {}", s.iss);
    println!("  iat:          {}", iso8601(s.iat));
    if let Some(t) = s.nbf {
        println!("  nbf:          {}", iso8601(t));
    }
    if let Some(t) = s.exp {
        println!("  exp:          {}", iso8601(t));
    }
    if s.entity_name.is_empty() {
        println!("  entity name:  (none)");
    } else {
        let mut first = true;
        for (lang, name) in &s.entity_name {
            if first {
                println!("  entity name:  {lang}: {name}");
                first = false;
            } else {
                println!("                {lang}: {name}");
            }
        }
    }
    println!(
        "  state actor:  {}",
        match s.is_state_actor {
            Some(true) => "yes",
            Some(false) => "no",
            None => "(undisclosed)",
        }
    );
    if let Some(st) = &s.status {
        println!("  status:       {} idx={}", st.type_, st.idx);
        println!("                {}", st.uri);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{build_jwt, is_state_actor_disclosure};
    use super::*;
    use serde_json::json;

    #[test]
    fn process_body_empty_array_returns_no_statements() {
        let outcome = process_body("did:tdw:abc", "[]", false).unwrap();
        assert!(matches!(outcome, LookupOutcome::NoStatements));
    }

    #[test]
    fn process_body_non_array_is_response_shape_error() {
        let err = process_body("did:tdw:abc", "{}", false).unwrap_err();
        assert!(matches!(err, BusinessEntityError::ResponseShape));
    }

    #[test]
    fn process_body_one_statement_returns_found() {
        let jwt = build_jwt(json!({}), vec![is_state_actor_disclosure(true)]);
        let body = serde_json::to_string(&vec![jwt]).unwrap();
        let outcome = process_body("did:tdw:abc", &body, false).unwrap();
        assert!(matches!(outcome, LookupOutcome::Found));
    }
}
