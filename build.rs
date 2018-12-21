extern crate bindgen;
extern crate cc;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    pkg_config::Config::new()
        .atleast_version("3.2.0")
        .probe("libkres")
        .unwrap();

    pkg_config::Config::new()
        .atleast_version("2.7.0")
        .probe("libknot")
        .unwrap();

    let lua_includes = pkg_config::Config::new()
        .probe("lua")
        .unwrap()
        .include_paths;

    cc::Build::new()
        .file("resolve.c")
        .include("src/knot-resolver")
        .include("src/knot-resolver/contrib")
        .include(lua_includes[0].to_str().unwrap())
        .compile("resolve");

    let bindings = bindgen::Builder::default()
        .header("resolve.h")
        .whitelist_function("lkr_.*")
        .rustified_enum("lkr_state")
        .raw_line("#[allow(bad_style)]")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Could not write bindings");
}
