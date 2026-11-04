fn main() {
    let expected = std::env::args_os().nth(1).expect("cargo home");
    let compiled = manifest_probe::manifest_dir!();
    assert!(std::path::Path::new(compiled).starts_with(expected));
}
