//! Mirrors cargo's build.rs `rustc-env` emit for `host-tuple` resolution.

fn main() {
    // `env!("TARGET")` is the triple this crate is being compiled *for*. For
    // wasm32 builds there is no meaningful rustc host triple; `host-tuple`
    // target config is a rustc-probe concept that cannot evaluate there.
    let target = std::env::var("TARGET").unwrap();
    println!("cargo:rustc-env=RUST_HOST_TARGET={target}");
}
