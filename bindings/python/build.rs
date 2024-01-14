use pyo3_tracing_subscriber::stubs::write_stub_files;

fn main() {
    let target_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pychecks/tracing_subscriber");
    eprintln!("target_dir: {:?}", target_dir);
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::remove_dir_all(&target_dir).unwrap();
    write_stub_files("pychecks", "tracing_subscriber", &target_dir).unwrap();
}
