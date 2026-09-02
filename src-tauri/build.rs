fn main() {
    // Tauri embeds the development Dock icon during code generation, but its
    // default build script does not reliably invalidate that output when an
    // icon file changes. Keep `tauri dev` and packaged bundles on the same
    // artwork without requiring a Cargo clean or a macOS icon-cache reset.
    println!("cargo:rerun-if-changed=icons/icon.png");
    println!("cargo:rerun-if-changed=icons/icon.icns");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    tauri_build::build()
}
