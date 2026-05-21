use std::path::PathBuf;

fn main() {
    let pvac_wasm_dir = PathBuf::from("../extension/src/lib/pvac-wasm");
    let src_dir = pvac_wasm_dir.join("src");
    let vendor_dir = pvac_wasm_dir.join("vendor");

    // Compile tiny-aes-c
    cc::Build::new()
        .file(vendor_dir.join("tiny-aes-c/aes.c"))
        .define("AES256", Some("1"))
        .define("ECB", Some("1"))
        .define("CBC", Some("0"))
        .define("CTR", Some("0"))
        .opt_level(3)
        .compile("tiny_aes");

    // Compile PVAC C++ sources
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++17")
        .file(src_dir.join("pvac_c_api.cpp"))
        .include(&src_dir)
        .include(vendor_dir.join("pvac"))
        .include(&vendor_dir)
        .define("NDEBUG", None)
        .define("AES256", Some("1"))
        .define("ECB", Some("1"))
        .define("CBC", Some("0"))
        .define("CTR", Some("0"))
        .opt_level(3);

    // Platform-specific flags
    if cfg!(target_arch = "aarch64") {
        // Enable ARM crypto extensions (AES/SHA) on Apple Silicon / ARM64
        build.flag("-march=armv8-a+crypto");
    } else {
        build.flag("-march=native");
    }

    build.compile("pvac");

    println!("cargo:rustc-link-lib=static=tiny_aes");
    println!("cargo:rustc-link-lib=static=pvac");

    // Re-run if sources change
    println!("cargo:rerun-if-changed={}", src_dir.join("pvac_c_api.cpp").display());
    println!("cargo:rerun-if-changed={}", src_dir.join("pvac_c_api.h").display());
    println!("cargo:rerun-if-changed={}", vendor_dir.join("tiny-aes-c/aes.c").display());
}
