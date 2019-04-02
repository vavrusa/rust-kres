extern crate bindgen;
extern crate cc;
extern crate fs_extra;
extern crate pkg_config;

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    cc::Build::new()
        .flag("-std=c99")
        .define("_BSD_SOURCE", None)
        .file("resolve.c")
        .include("src/knot-resolver")
        .include("src/knot-resolver/contrib")
        .compile("resolve");

    let bindings = bindgen::Builder::default()
        .header("resolve.h")
        .clang_args(["-I", "src/knot-resolver"].iter())
        .header("src/knot-resolver/lib/cache/api.h")
        .opaque_type("knot_mm_t")
        .opaque_type("kr_cdb_api")
        .whitelist_type("knot_rdata_t")
        .whitelist_type("knot_rdataset_t")
        .whitelist_type("knot_mm_t")
        .whitelist_type("kr_cache")
        .whitelist_type("kr_cache_p")
        .whitelist_type("ranked_rr_array_entry_t")
        .whitelist_function("lkr_.*")
        .whitelist_function("knot_rdataset_add")
        .rustified_enum("lkr_state")
        .raw_line("#[allow(bad_style)]")
        .generate()
        .expect("Unable to generate bindings");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Could not write bindings");

    let libkres_src_dir = out_dir.join("knot-resolver");

    // Copy knot-resolver submodule to the OUT_DIR
    assert!(out_dir.exists(), "OUT_DIR does not exist");
    let mut copy_options = fs_extra::dir::CopyOptions::new();
    copy_options.overwrite = true;
    copy_options.copy_inside = true;
    fs_extra::dir::copy(
        Path::new("src/knot-resolver"),
        &libkres_src_dir,
        &copy_options,
    )
    .expect("failed to copy libkres source code to OUT_DIR");
    assert!(libkres_src_dir.exists());

    if env::var_os("CARGO_FEATURE_STATIC").is_some() {
        println!(
            "cargo:rustc-link-search=native={}/lib",
            libkres_src_dir.display()
        );
        println!(
            "cargo:rustc-link-search=native={}/contrib",
            libkres_src_dir.display()
        );

        let compiler = cc::Build::new().get_compiler();
        let mut cflags = compiler
            .args()
            .iter()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<_>>();

        // Disable IPv6 unfairness
        cflags.push("-DFAVOUR_IPV6=0");

        // Build
        Command::new("make")
            .current_dir(&libkres_src_dir)
            .arg("lib")
            .arg("V=1")
            .arg("BUILDMODE=static")
            .arg("LIBRARY_ONLY=yes")
            .env("CC", compiler.path())
            .env("CFLAGS", cflags.join(" "))
            .status()
            .expect("failed to build libkres");

        // lib name fix
        fs::rename(
            format!("{}/contrib/contrib.a", libkres_src_dir.display()),
            format!("{}/contrib/libcontrib.a", libkres_src_dir.display()),
        )
        .expect("failed to fix lib name");

        println!("cargo:rustc-link-lib=static=kres");
        println!("cargo:rustc-link-lib=static=contrib");
    } else {
        pkg_config::Config::new()
            .atleast_version("3.2.0")
            .probe("libkres")
            .unwrap();
    }

    pkg_config::Config::new()
        .atleast_version("2.7.0")
        .probe("libknot")
        .unwrap();

    println!("cargo:rustc-link-lib=dnssec");
    println!("cargo:rustc-link-lib=gnutls");
}
