fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_FEATURE_PIC").is_ok() {
        // Merge all sections into .text — single-section PE
        println!("cargo:rustc-link-arg=/MERGE:.rdata=.text");
        println!("cargo:rustc-link-arg=/MERGE:.data=.text");
        println!("cargo:rustc-link-arg=/MERGE:.pdata=.text");

        // Strip the CRT entirely — no main(), no heap init, no runtime
        println!("cargo:rustc-link-arg=/NODEFAULTLIB");

        // Console subsystem (for return code visibility)
        println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");

        // Custom entry point — our _pic_entry function
        println!("cargo:rustc-link-arg-bin=pic_example=/ENTRY:_pic_entry");
    }
}
