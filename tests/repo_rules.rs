//! Repository-wide rules from PLAN.md section 2 that are easy to break by
//! accident. Reads the source tree read-only.

use std::fs;
use std::path::{Path, PathBuf};

const EM_DASH: char = '\u{2014}';

fn text_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            text_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rs" | "md" | "html" | "js" | "css" | "json" | "toml" | "yml" | "yaml")
        ) {
            out.push(path);
        }
    }
}

#[test]
fn no_em_dashes_in_docs_comments_or_ui() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "static", "tests", "openapi"] {
        text_files(&root.join(dir), &mut files);
    }
    for file in ["AGENT.md", "PLAN.md", "Cargo.toml", "README.md"] {
        let path = root.join(file);
        if path.exists() {
            files.push(path);
        }
    }
    assert!(files.len() > 10, "found only {files:?}");
    let offenders: Vec<_> = files
        .iter()
        .filter(|path| fs::read_to_string(path).unwrap().contains(EM_DASH))
        .collect();
    assert!(offenders.is_empty(), "em dash in {offenders:?}");
}

/// Every `OATH_*` variable the service reads is documented in the README.
#[test]
fn readme_documents_every_config_variable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = fs::read_to_string(root.join("src/config.rs")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap_or_default();
    let mut vars: Vec<&str> = config
        .split('"')
        .filter(|s| s.starts_with("OATH_") && s.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
        .collect();
    vars.sort_unstable();
    vars.dedup();
    assert_eq!(vars.len(), 7, "{vars:?}");
    let missing: Vec<_> = vars
        .iter()
        .filter(|v| !readme.contains(&format!("`{v}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "README.md does not document {missing:?}"
    );
}
