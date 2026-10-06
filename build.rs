fn main() {
    for path in [
        "schemas/tunnelrpc.capnp",
        "schemas/quic_metadata_protocol.capnp",
        "schemas/go.capnp",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=CAPNP");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    if let Some(compiler) = std::env::var_os("CAPNP") {
        capnpc::CompilerCommand::new()
            .capnp_executable(compiler)
            .src_prefix("schemas")
            .import_path("schemas")
            .default_parent_module(vec!["protocol".into()])
            .file("schemas/tunnelrpc.capnp")
            .file("schemas/quic_metadata_protocol.capnp")
            .run()
            .expect("compile Cloudflare wire schemas");
    } else {
        for name in ["tunnelrpc_capnp.rs", "quic_metadata_protocol_capnp.rs"] {
            let source = std::path::Path::new("src/protocol/generated").join(name);
            println!("cargo:rerun-if-changed={}", source.display());
            std::fs::copy(source, out.join(name))
                .expect("checked-in Cap'n Proto bindings; set CAPNP to regenerate");
        }
    }
}
