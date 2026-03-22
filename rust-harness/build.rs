use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(cmd: &mut Command, what: &str) {
    let status = cmd.status().unwrap_or_else(|e| panic!("failed to start {}: {}", what, e));
    if !status.success() {
        panic!("{} failed with status {}", what, status);
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=ASB_ROOT");
    println!("cargo:rerun-if-env-changed=NASM");
    println!("cargo:rerun-if-changed=build.rs");

    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing"));
    // Default: asb_root is the parent of the rust-harness directory
    let asb_root = env::var("ASB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| crate_dir.parent().unwrap_or(&crate_dir).to_path_buf());

    let include_dir = asb_root.join("include");
    let asm_dir = asb_root.join("asm");
    let cshim_dir = asb_root.join("cshim");

    let required = [
        include_dir.join("assemblersky.h"),
        asm_dir.join("cbor_scan.asm"),
        asm_dir.join("car_scan.asm"),
        asm_dir.join("post_extract.asm"),
        asm_dir.join("util.asm"),
        cshim_dir.join("assemblersky_exports.c"),
    ];

    for p in &required {
        if !p.exists() {
            panic!(
                "required Assemblersky source not found: {}\nHint: set ASB_ROOT to the Assemblersky project root.",
                p.display()
            );
        }
        println!("cargo:rerun-if-changed={}", p.display());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR missing"));
    let obj_dir = out_dir.join("asb-obj");
    std::fs::create_dir_all(&obj_dir).expect("failed to create object directory");

    let nasm = env::var("NASM").unwrap_or_else(|_| "nasm".to_string());
    let asm_sources = ["cbor_scan.asm", "car_scan.asm", "post_extract.asm", "util.asm"];

    let mut asm_objects: Vec<PathBuf> = Vec::new();
    for src in asm_sources {
        let src_path = asm_dir.join(src);
        let obj_path = obj_dir.join(Path::new(src).file_stem().unwrap()).with_extension("o");
        let mut cmd = Command::new(&nasm);
        cmd.arg("-felf64")
            .arg("-g")
            .arg("-F").arg("dwarf")
            .arg("-o").arg(&obj_path)
            .arg(&src_path);
        run(&mut cmd, &format!("nasm compiling {}", src_path.display()));
        asm_objects.push(obj_path);
    }

    let mut cc_build = cc::Build::new();
    cc_build
        .file(cshim_dir.join("assemblersky_exports.c"))
        .include(&include_dir)
        .warnings(true)
        .extra_warnings(true)
        .flag_if_supported("-fno-omit-frame-pointer");

    for obj in &asm_objects {
        cc_build.object(obj);
    }

    cc_build.compile("assemblersky");
    println!("cargo:rustc-link-lib=static=assemblersky");
}
