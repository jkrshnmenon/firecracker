fn main() {
    println!("cargo:rustc-link-search=./src/xdc/");
    println!("cargo:rustc-link-lib=xdc");
}
