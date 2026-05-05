use std::collections::HashMap;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use serde_json::Value;
use tracing::debug;

use swiyu_core::did::DID;
use swiyu_core::diddoc::{DIDDoc, PublicKey, PublicKeyJWK};
use swiyu_core::didlog::{DIDDocState, DIDLog};
use swiyu_core::statuslist::{StatusList, StatusValue};
use swiyu_core::truststatement::TrustStatement;

use crate::cmd::http::{FetchOutcome, fetch_text};
use crate::cmd::{iso8601, resolve_did};
use crate::keystore::KeyStore;

use super::{TrustError, build_endpoint};

pub use super::TrustError as VerifyError;

pub struct VerifyArgs {
    pub did: String,
    pub trust_registry_url: Option<String>,
    pub trust_issuer: Option<String>,
}

#[derive(Debug)]
pub enum VerifyOutcome {
    Trusted,
    Untrusted,
}

pub fn cmd_verify(store: &KeyStore, args: VerifyArgs) -> Result<VerifyOutcome, VerifyError> {
    let base_url = args
        .trust_registry_url
        .ok_or(TrustError::TrustRegistryUrlMissing)?;
    let expected_issuer = args.trust_issuer.ok_or(TrustError::TrustIssuerMissing)?;
    let did = resolve_did(store, &args.did)?;
    let endpoint = build_endpoint(&base_url, &did);
    debug!("GET {endpoint}");
    let did_str = did.to_string();

    let array: Vec<String> = match fetch_text(&endpoint)? {
        FetchOutcome::NotFound => Vec::new(),
        FetchOutcome::Ok(body) => {
            serde_json::from_str(&body).map_err(|_| TrustError::ResponseShape)?
        }
    };

    if array.is_empty() {
        print_header(&did_str, &expected_issuer);
        println!();
        println!("Verdict: 0 trusted statements out of 0 — entity is untrusted.");
        return Ok(VerifyOutcome::Untrusted);
    }

    let mut decoded = Vec::with_capacity(array.len());
    for (i, jwt) in array.iter().enumerate() {
        let s = TrustStatement::try_from_jwt(jwt)
            .map_err(|source| TrustError::Statement { n: i + 1, source })?;
        decoded.push(s);
    }
    decoded.sort_by_key(|s| std::cmp::Reverse(s.iat));

    let mut ctx = VerifyContext::new(expected_issuer);
    let now = Utc::now().timestamp().max(0) as u64;

    let mut reports = Vec::with_capacity(decoded.len());
    for stmt in &decoded {
        reports.push(verify_one(stmt, now, &mut ctx)?);
    }

    print_header(&did_str, &ctx.expected_issuer);
    for (i, r) in reports.iter().enumerate() {
        println!();
        print_report(i + 1, r);
    }
    println!();
    let trusted_count = reports.iter().filter(|r| r.verdict).count();
    let total = reports.len();
    if trusted_count > 0 {
        println!(
            "Verdict: {trusted_count} trusted statement{} out of {total} — entity is trusted.",
            if trusted_count == 1 { "" } else { "s" }
        );
        Ok(VerifyOutcome::Trusted)
    } else {
        println!("Verdict: 0 trusted statements out of {total} — entity is untrusted.");
        Ok(VerifyOutcome::Untrusted)
    }
}

// ── Verification ─────────────────────────────────────────────────────────────

/// Per-invocation state threaded through the verification chain.
///
/// Holds the expected SWIYU trust authority DID (used for both the issuer-allowlist check
/// and the status-list signature check), plus two URL-keyed caches so a single command run
/// performs at most one fetch per unique issuer DID and one per unique status-list URL,
/// regardless of how many statements reference them.
struct VerifyContext {
    /// The well-known SWIYU trust issuer DID (from `--trust-issuer` /
    /// `SWIYU_TRUST_ISSUER_DID`). `payload.iss` of every trust statement must equal this,
    /// and the status list it points to must be signed by this same DID. Empirically
    /// confirmed against the SWIYU integration environment: SWIYU signs both the trust
    /// statement and its status list with the same DID.
    expected_issuer: String,
    /// Cache of issuer DID documents, keyed by DID string. Populated on first reference;
    /// re-used for both the trust-statement signature check and the status-list signature
    /// check (which both resolve their `kid` against the issuer DID's verification methods).
    issuer_docs: HashMap<String, DIDDoc>,
    /// Cache of decoded, signature-verified status lists, keyed by URL. Parsing
    /// (decompression, slot-width validation) is done by [`StatusList::from_payload`];
    /// signature verification is done locally before insertion.
    status_lists: HashMap<String, StatusList>,
}

impl VerifyContext {
    fn new(expected_issuer: String) -> Self {
        Self {
            expected_issuer,
            issuer_docs: HashMap::new(),
            status_lists: HashMap::new(),
        }
    }
}

#[derive(Debug)]
struct Report<'s> {
    statement: &'s TrustStatement,
    iss_check: Check,
    signature_check: Check,
    freshness_check: Check,
    status_check: Check,
    verdict: bool,
}

#[derive(Debug)]
enum Check {
    Ok(String),
    Fail(String),
    Skip(String),
}

impl Check {
    fn passed(&self) -> bool {
        matches!(self, Check::Ok(_))
    }

    fn marker(&self) -> &'static str {
        match self {
            Check::Ok(_) => "[ok]  ",
            Check::Fail(_) => "[fail]",
            Check::Skip(_) => "[skip]",
        }
    }

    fn message(&self) -> &str {
        match self {
            Check::Ok(s) | Check::Fail(s) | Check::Skip(s) => s,
        }
    }
}

fn verify_one<'s>(
    stmt: &'s TrustStatement,
    now: u64,
    ctx: &mut VerifyContext,
) -> Result<Report<'s>, VerifyError> {
    // 1. Issuer allowlist.
    let iss_check = if stmt.iss == ctx.expected_issuer {
        Check::Ok("matches expected issuer".into())
    } else {
        Check::Fail(format!("{} (does not match expected issuer)", stmt.iss))
    };

    // 2-3. Issuer DID resolution + signature.
    let signature_check = if !iss_check.passed() {
        Check::Skip("(issuer mismatch)".into())
    } else {
        verify_signature(stmt, ctx)?
    };

    // 4. Freshness — independent of iss/signature.
    let freshness_check = check_freshness(stmt, now);

    // 5. Status list — only meaningful if the signature is trusted.
    let status_check = if !signature_check.passed() {
        Check::Skip("(would only matter if signature were trusted)".into())
    } else {
        check_status(stmt, ctx)?
    };

    let verdict = iss_check.passed()
        && signature_check.passed()
        && freshness_check.passed()
        && status_check.passed();

    Ok(Report {
        statement: stmt,
        iss_check,
        signature_check,
        freshness_check,
        status_check,
        verdict,
    })
}

fn verify_signature(stmt: &TrustStatement, ctx: &mut VerifyContext) -> Result<Check, VerifyError> {
    if stmt.alg != "ES256" {
        return Ok(Check::Fail(format!(
            "unsupported alg '{}' (expected ES256)",
            stmt.alg
        )));
    }
    let kid_did = match stmt.kid.split_once('#') {
        Some((d, _)) => d,
        None => return Ok(Check::Fail(format!("kid '{}' has no fragment", stmt.kid))),
    };

    let doc = load_issuer_doc(kid_did, &mut ctx.issuer_docs)?;
    let vk = match find_verifying_key(doc, &stmt.kid) {
        Ok(vk) => vk,
        Err(reason) => return Ok(Check::Fail(reason)),
    };

    let signature = match p256::ecdsa::Signature::from_slice(&stmt.signature) {
        Ok(s) => s,
        Err(_) => {
            return Ok(Check::Fail(
                "signature bytes are not a valid ES256 signature".into(),
            ));
        }
    };
    use p256::ecdsa::signature::Verifier;
    match vk.verify(stmt.signing_input.as_bytes(), &signature) {
        Ok(()) => Ok(Check::Ok(format!("valid (kid: {})", stmt.kid))),
        Err(_) => Ok(Check::Fail("signature does not verify".into())),
    }
}

fn check_freshness(stmt: &TrustStatement, now: u64) -> Check {
    if let Some(nbf) = stmt.nbf
        && now < nbf
    {
        return Check::Fail(format!("now < nbf ({} < {})", iso8601(now), iso8601(nbf)));
    }
    if let Some(exp) = stmt.exp
        && now >= exp
    {
        return Check::Fail(format!("expired at {}", iso8601(exp)));
    }
    let nbf = stmt.nbf.map(iso8601).unwrap_or_else(|| "—".into());
    let exp = stmt.exp.map(iso8601).unwrap_or_else(|| "—".into());
    Check::Ok(format!("now within nbf..exp ({nbf}..{exp})"))
}

fn check_status(stmt: &TrustStatement, ctx: &mut VerifyContext) -> Result<Check, VerifyError> {
    let info = match &stmt.status {
        Some(s) => s,
        None => return Ok(Check::Fail("no status_list claim in payload".into())),
    };
    let list = load_status_list(info.uri(), ctx)?;
    let bits = list.bits();
    let value = list.value_at(info.idx())?;
    Ok(match value {
        StatusValue::Valid => Check::Ok(format!("valid (idx={}, bits={bits})", info.idx())),
        StatusValue::Revoked => Check::Fail(format!("revoked (idx={}, bits={bits})", info.idx())),
        StatusValue::Suspended => {
            Check::Fail(format!("suspended (idx={}, bits={bits})", info.idx()))
        }
        StatusValue::Reserved(n) => {
            Check::Fail(format!("reserved={n} (idx={}, bits={bits})", info.idx()))
        }
    })
}

fn load_issuer_doc<'a>(
    iss_did: &str,
    cache: &'a mut HashMap<String, DIDDoc>,
) -> Result<&'a DIDDoc, VerifyError> {
    if !cache.contains_key(iss_did) {
        let did = DID::from_str(iss_did).map_err(|e| VerifyError::IssuerResolution {
            iss: iss_did.to_string(),
            reason: e.to_string(),
        })?;
        let log_url = did.log_url();
        debug!("fetching issuer DID log: {log_url}");
        let text = match fetch_text(&log_url)? {
            FetchOutcome::Ok(t) => t,
            FetchOutcome::NotFound => {
                return Err(VerifyError::IssuerResolution {
                    iss: iss_did.to_string(),
                    reason: format!("'{log_url}' returned 404"),
                });
            }
        };
        let log = DIDLog::try_from_jsonl(&text).map_err(|e| VerifyError::IssuerResolution {
            iss: iss_did.to_string(),
            reason: format!("log parse: {e}"),
        })?;
        let last = log
            .entries()
            .last()
            .ok_or_else(|| VerifyError::IssuerResolution {
                iss: iss_did.to_string(),
                reason: "log is empty".into(),
            })?;
        let doc_value = match last.did_doc_state() {
            DIDDocState::Value(v) => v,
            DIDDocState::Patch(_) => {
                return Err(VerifyError::IssuerResolution {
                    iss: iss_did.to_string(),
                    reason: "latest entry's state is a JSON Patch".into(),
                });
            }
        };
        let doc = DIDDoc::try_from(doc_value)?;
        cache.insert(iss_did.to_string(), doc);
    }
    Ok(cache.get(iss_did).expect("just inserted"))
}

fn find_verifying_key(doc: &DIDDoc, kid: &str) -> Result<p256::ecdsa::VerifyingKey, String> {
    let vm = doc
        .verification_method()
        .iter()
        .find(|vm| vm.id() == kid)
        .ok_or_else(|| format!("no verification method with id '{kid}'"))?;
    let jwk = match vm.public_key() {
        PublicKey::Jwk(jwk) => jwk,
        PublicKey::Multibase(_) => {
            return Err("verification method publicKey is not a JWK".into());
        }
    };
    let ec = match jwk.as_ref() {
        PublicKeyJWK::EC(k) => k,
        other => return Err(format!("expected EC JWK, got {}", other.kty())),
    };
    p256::ecdsa::VerifyingKey::try_from(ec).map_err(|e| e.to_string())
}

fn load_status_list<'a>(
    url: &str,
    ctx: &'a mut VerifyContext,
) -> Result<&'a StatusList, VerifyError> {
    if !ctx.status_lists.contains_key(url) {
        let text = match fetch_text(url)? {
            FetchOutcome::Ok(t) => t,
            FetchOutcome::NotFound => {
                return Err(VerifyError::StatusListMalformed {
                    url: url.to_string(),
                    reason: "registry returned 404".into(),
                });
            }
        };
        let list = parse_and_verify_status_list(url, text.trim(), ctx)?;
        ctx.status_lists.insert(url.to_string(), list);
    }
    Ok(ctx.status_lists.get(url).expect("just inserted"))
}

fn parse_and_verify_status_list(
    url: &str,
    jwt: &str,
    ctx: &mut VerifyContext,
) -> Result<StatusList, VerifyError> {
    let segs: Vec<&str> = jwt.split('.').collect();
    if segs.len() != 3 {
        return Err(VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: format!("expected 3 dot-separated parts, got {}", segs.len()),
        });
    }
    let header_bytes =
        URL_SAFE_NO_PAD
            .decode(segs[0])
            .map_err(|e| VerifyError::StatusListMalformed {
                url: url.to_string(),
                reason: format!("header not base64url: {e}"),
            })?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|e| VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: format!("header not JSON: {e}"),
        })?;
    let payload_bytes =
        URL_SAFE_NO_PAD
            .decode(segs[1])
            .map_err(|e| VerifyError::StatusListMalformed {
                url: url.to_string(),
                reason: format!("payload not base64url: {e}"),
            })?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: format!("payload not JSON: {e}"),
        })?;
    let signature =
        URL_SAFE_NO_PAD
            .decode(segs[2])
            .map_err(|e| VerifyError::StatusListMalformed {
                url: url.to_string(),
                reason: format!("signature not base64url: {e}"),
            })?;

    // Verify alg is ES256 and kid points at the expected issuer DID.
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("(missing)");
    if alg != "ES256" {
        return Err(VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: format!("unsupported alg '{alg}' (expected ES256)"),
        });
    }
    let kid = header.get("kid").and_then(Value::as_str).ok_or_else(|| {
        VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: "missing 'kid' in header".into(),
        }
    })?;
    let kid_did =
        kid.split_once('#')
            .map(|(d, _)| d)
            .ok_or_else(|| VerifyError::StatusListMalformed {
                url: url.to_string(),
                reason: format!("kid '{kid}' has no fragment"),
            })?;
    if kid_did != ctx.expected_issuer {
        return Err(VerifyError::StatusListMalformed {
            url: url.to_string(),
            reason: format!(
                "kid's DID '{kid_did}' does not match expected issuer '{}'",
                ctx.expected_issuer
            ),
        });
    }

    // Verify signature.
    let doc = load_issuer_doc(kid_did, &mut ctx.issuer_docs)?;
    let vk = find_verifying_key(doc, kid).map_err(|reason| VerifyError::StatusListMalformed {
        url: url.to_string(),
        reason: format!("issuer key resolution: {reason}"),
    })?;
    let sig = p256::ecdsa::Signature::from_slice(&signature)
        .map_err(|_| VerifyError::StatusListSignatureInvalid)?;
    let signing_input = format!("{}.{}", segs[0], segs[1]);
    use p256::ecdsa::signature::Verifier;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::StatusListSignatureInvalid)?;

    // Decode + decompress + bit-width validate via core. Errors propagate as
    // TrustError::StatusList(StatusListError) through `?`.
    Ok(StatusList::from_payload(&payload)?)
}

// ── Output ───────────────────────────────────────────────────────────────────

fn print_header(did: &str, expected_issuer: &str) {
    println!("Trust statements for {did}");
    println!("Expected issuer:    {expected_issuer}");
}

fn print_report(n: usize, r: &Report<'_>) {
    let s = r.statement;
    println!("#{n}  {}", s.vct);
    println!("  iat (issued at):    {}", iso8601(s.iat));
    println!(
        "  iss (issuer):       {} {}",
        r.iss_check.marker(),
        r.iss_check.message()
    );
    println!(
        "  signature:          {} {}",
        r.signature_check.marker(),
        r.signature_check.message()
    );
    println!(
        "  freshness:          {} {}",
        r.freshness_check.marker(),
        r.freshness_check.message()
    );
    println!(
        "  status:             {} {}",
        r.status_check.marker(),
        r.status_check.message()
    );
    if !s.entity_name.is_empty() {
        let mut first = true;
        for (lang, name) in &s.entity_name {
            if first {
                println!("  entity name:        {lang}: {name}");
                first = false;
            } else {
                println!("                      {lang}: {name}");
            }
        }
    }
    if let Some(b) = s.is_state_actor {
        println!("  state actor:        {}", if b { "yes" } else { "no" });
    }
    println!(
        "  verdict:            {}  {}",
        if r.verdict { "[ok]  " } else { "[fail]" },
        if r.verdict { "trusted" } else { "untrusted" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bitstring slot-reading is exhaustively covered by `swiyu_core::statuslist`'s
    // unit tests; we don't duplicate that surface here.

    #[test]
    fn check_freshness_within_window() {
        let stmt = stub_statement(Some(1000), Some(2000));
        let c = check_freshness(&stmt, 1500);
        assert!(c.passed());
    }

    #[test]
    fn check_freshness_before_nbf() {
        let stmt = stub_statement(Some(1000), Some(2000));
        let c = check_freshness(&stmt, 500);
        assert!(matches!(c, Check::Fail(_)));
    }

    #[test]
    fn check_freshness_after_exp() {
        let stmt = stub_statement(Some(1000), Some(2000));
        let c = check_freshness(&stmt, 3000);
        assert!(matches!(c, Check::Fail(_)));
    }

    fn stub_statement(nbf: Option<u64>, exp: Option<u64>) -> TrustStatement {
        TrustStatement {
            vct: "TrustStatementIdentityV1".into(),
            iss: "did:tdw:abc".into(),
            iat: 1000,
            nbf,
            exp,
            entity_name: Default::default(),
            is_state_actor: None,
            status: None,
            kid: "did:tdw:abc#assert-key-02".into(),
            alg: "ES256".into(),
            signing_input: String::new(),
            signature: vec![],
        }
    }
}
