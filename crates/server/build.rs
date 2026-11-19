//! With the `ui` feature, embed the built web UI (`crates/web/dist`, or
//! `$TUNNEL_UI_DIST`) as static byte slices: they live in the binary's
//! read-only data, so the kernel pages them in on demand and can drop them
//! again under memory pressure. Pre-compressed `.br`/`.gz` siblings are
//! served when the browser accepts them.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TUNNEL_UI_DIST");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let mut code = String::from("pub static ASSETS: &[Asset] = &[\n");
    if std::env::var_os("CARGO_FEATURE_UI").is_some() {
        let dist = std::env::var_os("TUNNEL_UI_DIST")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../web/dist"));
        let dist = dist.canonicalize().unwrap_or_else(|_| {
            panic!("feature `ui` needs the built web UI in {} (run crates/web/build.sh)", dist.display())
        });
        println!("cargo:rerun-if-changed={}", dist.display());
        let mut files = Vec::new();
        collect(&dist, &dist, &mut files);
        files.sort();
        assert!(files.iter().any(|f| f == "index.html"), "{} has no index.html", dist.display());
        for rel in &files {
            if rel.ends_with(".br") || rel.ends_with(".gz") {
                continue;
            }
            let path = dist.join(rel);
            println!("cargo:rerun-if-changed={}", path.display());
            let sibling = |ext: &str| {
                let p = dist.join(format!("{rel}.{ext}"));
                if p.is_file() {
                    println!("cargo:rerun-if-changed={}", p.display());
                    format!("Some(include_bytes!({:?}))", p.display().to_string())
                } else {
                    "None".to_string()
                }
            };
            writeln!(
                code,
                "    Asset {{ path: {:?}, mime: {:?}, raw: include_bytes!({:?}), br: {}, gz: {} }},",
                format!("/{rel}"),
                mime(rel),
                path.display().to_string(),
                sibling("br"),
                sibling("gz"),
            )
            .unwrap();
        }
    }
    code.push_str("];\n");
    std::fs::write(out.join("ui_assets.rs"), code).expect("writing ui_assets.rs");
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("reading ui dist") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(root, &path, out);
        } else if path.is_file() {
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            out.push(rel);
        }
    }
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "wasm" => "application/wasm",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
