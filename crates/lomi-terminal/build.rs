use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=src/supervisor/macos_snapshot.c");
    println!("cargo:rerun-if-changed=src/supervisor/macos_coalition/capability.c");
    println!("cargo:rerun-if-changed=src/supervisor/macos_coalition/abi.h");
    println!("cargo:rerun-if-changed=src/supervisor/macos_privileged/capability.c");
    println!("cargo:rerun-if-changed=src/supervisor/macos_privileged/abi.h");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=AR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    let architecture = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => panic!("unsupported macOS architecture: {other}"),
    };
    let deployment = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| {
        let output = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args([
                "--print",
                "deployment-target",
                "--target",
                &env::var("TARGET").unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "query Rust macOS deployment target"
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .strip_prefix("MACOSX_DEPLOYMENT_TARGET=")
            .unwrap()
            .to_owned()
    });
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut helpers = vec![(
        "macos_privileged",
        "src/supervisor/macos_privileged/capability.c",
    )];
    println!("cargo:rustc-link-lib=bsm");
    if env::var_os("CARGO_FEATURE_EXPERIMENTAL_MACOS_SESSION_CLEANUP").is_some() {
        helpers.push(("macos_snapshot", "src/supervisor/macos_snapshot.c"));
    }
    if env::var_os("CARGO_FEATURE_EXPERIMENTAL_MACOS_COALITION_CLEANUP").is_some() {
        helpers.push((
            "macos_coalition",
            "src/supervisor/macos_coalition/capability.c",
        ));
    }
    for (name, source) in helpers {
        let object = out.join(format!("{name}.o"));
        let library = out.join(format!("liblomi_{name}.a"));
        assert!(
            Command::new(env::var_os("CC").unwrap_or_else(|| "cc".into()))
                .args(["-arch", architecture])
                .arg(format!("-mmacosx-version-min={deployment}"))
                .args([
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-c", source, "-o"
                ])
                .arg(&object)
                .status()
                .unwrap()
                .success(),
            "compile macOS metadata snapshot helper"
        );
        assert!(
            Command::new(env::var_os("AR").unwrap_or_else(|| "ar".into()))
                .arg("crs")
                .arg(&library)
                .arg(&object)
                .status()
                .unwrap()
                .success(),
            "archive macOS metadata snapshot helper"
        );
        println!("cargo:rustc-link-search=native={}", out.display());
        println!("cargo:rustc-link-lib=static=lomi_{name}");
    }
}
