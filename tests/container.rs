//! Rules for the container files from PLAN.md section 13. YAML and
//! Dockerfile syntax are checked by building the image; these tests guard
//! the security properties that are easy to lose in an edit.

use std::fs;
use std::path::Path;

fn read(name: &str) -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(name))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Dockerfile stages, split on `FROM` lines.
fn stages(dockerfile: &str) -> Vec<String> {
    let mut stages: Vec<String> = Vec::new();
    for line in dockerfile.lines() {
        if line.trim_start().to_ascii_uppercase().starts_with("FROM ") {
            stages.push(String::new());
        }
        if let Some(stage) = stages.last_mut() {
            stage.push_str(line);
            stage.push('\n');
        }
    }
    stages
}

#[test]
fn dockerfile_builds_on_rust_bookworm_and_runs_on_slim() {
    let dockerfile = read("Dockerfile");
    let stages = stages(&dockerfile);
    assert_eq!(stages.len(), 2, "builder and runtime stages");
    assert!(stages[0].contains("FROM rust:1-bookworm AS build"), "{}", stages[0]);
    assert!(stages[0].contains("libpcsclite-dev") && stages[0].contains("pkg-config"));
    assert!(stages[0].contains("cargo build --release --locked"));
    assert!(stages[1].starts_with("FROM debian:bookworm-slim"), "{}", stages[1]);
}

#[test]
fn runtime_image_installs_only_pcsc_and_certificates() {
    let runtime = stages(&read("Dockerfile")).pop().unwrap();
    let install = runtime
        .lines()
        .find(|l| l.contains("apt-get install"))
        .expect("runtime apt-get install");
    let packages: Vec<&str> = install
        .split_whitespace()
        .skip_while(|w| *w != "install")
        .skip(1)
        .filter(|w| !w.starts_with('-') && *w != "&&" && *w != "\\")
        .take_while(|w| !w.contains("rm"))
        .collect();
    assert_eq!(packages, ["libpcsclite1", "ca-certificates"], "{install}");
}

#[test]
fn runtime_image_runs_as_non_root() {
    let runtime = stages(&read("Dockerfile")).pop().unwrap();
    let user = runtime
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with("USER "))
        .expect("USER in runtime stage");
    let uid = user.trim_start()["USER ".len()..].split(':').next().unwrap().trim();
    let uid: u32 = uid.parse().expect("numeric uid, so Kubernetes-style runAsNonRoot checks work");
    assert!(uid >= 1000, "{user}");
    assert!(runtime.contains("ENTRYPOINT [\"/usr/local/bin/oath-web\"]"));
}

#[test]
fn dockerignore_keeps_secrets_and_build_output_out_of_the_context() {
    let ignore = read(".dockerignore");
    let entries: Vec<&str> = ignore.lines().map(str::trim).collect();
    for required in [".env", ".git", "target"] {
        assert!(
            entries.iter().any(|e| e.trim_start_matches('/') == required),
            ".dockerignore must list {required}"
        );
    }
}

#[test]
fn compose_hardens_the_container() {
    let compose = read("docker-compose.yml");
    for required in [
        "read_only: true",
        "cap_drop: [ALL]",
        "no-new-privileges:true",
        "/run/pcscd:/run/pcscd",
        "restart: unless-stopped",
        "external: true",
    ] {
        assert!(compose.contains(required), "docker-compose.yml lacks {required}");
    }
}

#[test]
fn compose_publishes_no_host_port() {
    let compose = read("docker-compose.yml");
    assert!(
        !compose.lines().any(|l| l.trim_start().starts_with("ports:")),
        "only Traefik may reach the service"
    );
}

#[test]
fn traefik_headers_middleware_matches_the_app() {
    let compose = read("docker-compose.yml");
    assert!(
        compose.contains("traefik.http.routers.oath.middlewares: oath-lan,oath-headers"),
        "router must use both middlewares"
    );
    let csp = format!(
        "traefik.http.middlewares.oath-headers.headers.contentSecurityPolicy: \"{}\"",
        oath_web::api::security::CSP
    );
    assert!(compose.contains(&csp), "CSP in compose must equal the app's");
    for required in [
        "traefik.http.middlewares.oath-headers.headers.contentTypeNosniff: \"true\"",
        "traefik.http.middlewares.oath-headers.headers.frameDeny: \"true\"",
        "traefik.http.middlewares.oath-headers.headers.referrerPolicy: \"no-referrer\"",
        "traefik.http.middlewares.oath-headers.headers.customResponseHeaders.Cache-Control: \"no-store\"",
        "traefik.http.middlewares.oath-lan.ipallowlist.sourcerange:",
        "traefik.http.services.oath.loadbalancer.server.port: \"8080\"",
    ] {
        assert!(compose.contains(required), "docker-compose.yml lacks {required}");
    }
}
