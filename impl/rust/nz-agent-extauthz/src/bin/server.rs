// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! `nz-agent-extauthz` server binary: hosts the `Authorization` ext_authz
//! gRPC service on a TCP listener, backed by a
//! [`nz_agent::waypoint::TableAuthzHook`] built from `--grant` CLI flags.
//!
//! **This binary is a demo/reference host, not a production deployment
//! artifact.** A real deployment supplies its own `AuthzHook`
//! implementation (see `lib.rs`'s "Tracked gap: the real `AuthzHook`"
//! module docs) — swap `TableAuthzHook` for that implementation and this
//! `main` otherwise stays the same (construct the hook, pass it to
//! `ExtAuthzService::new`, serve).
//!
//! ```text
//! nz-agent-extauthz --listen 0.0.0.0:9191 --consuming-authority gateway-a \
//!     --grant signer-1=non_idempotent_write --grant signer-2=read_only
//! ```

use nz_agent::waypoint::{EffectClass, TableAuthzHook};
use nz_agent_extauthz::pb::authorization_server::AuthorizationServer;
use nz_agent_extauthz::ExtAuthzService;
use tonic::transport::Server;

fn parse_effect(s: &str) -> Result<EffectClass, String> {
    match s {
        "read_only" => Ok(EffectClass::ReadOnly),
        "idempotent_write" => Ok(EffectClass::IdempotentWrite),
        "non_idempotent_write" => Ok(EffectClass::NonIdempotentWrite),
        "destructive" => Ok(EffectClass::Destructive),
        other => Err(format!("unrecognized effect class {other:?} (expected one of: read_only, idempotent_write, non_idempotent_write, destructive)")),
    }
}

fn parse_grant(s: &str) -> Result<(String, EffectClass), String> {
    let (signer, effect) = s.split_once('=').ok_or_else(|| format!("--grant value {s:?} must be SIGNER=EFFECT"))?;
    Ok((signer.to_string(), parse_effect(effect)?))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1:9191".to_string();
    let mut consuming_authority = "gateway-a".to_string();
    let mut grants: Vec<(String, EffectClass)> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => listen = args.next().ok_or("--listen requires a value")?,
            "--consuming-authority" => consuming_authority = args.next().ok_or("--consuming-authority requires a value")?,
            "--grant" => {
                let raw = args.next().ok_or("--grant requires a SIGNER=EFFECT value")?;
                grants.push(parse_grant(&raw)?);
            }
            other => return Err(format!("unrecognized argument {other:?}").into()),
        }
    }

    let grant_refs: Vec<(&str, EffectClass)> = grants.iter().map(|(s, e)| (s.as_str(), *e)).collect();
    let hook = TableAuthzHook::new(&consuming_authority, &grant_refs);
    let service = ExtAuthzService::new(hook);

    let addr = listen.parse()?;
    eprintln!("nz-agent-extauthz: listening on {addr}, consuming_authority={consuming_authority:?}, {} grant(s)", grants.len());

    Server::builder().add_service(AuthorizationServer::new(service)).serve(addr).await?;

    Ok(())
}
