#[cfg(all(target_os = "windows", feature = "native-verification"))]
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let result = if arguments.first().map(String::as_str) == Some("--native-verification-child") {
        hybridcipher_windows_cloud_provider::verification::child(&arguments[1..])
    } else if let Some(path) = arguments.first() {
        hybridcipher_windows_cloud_provider::verification::run(std::path::Path::new(path))
    } else {
        Err("Pass a new absolute disposable verification directory".into())
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(all(target_os = "windows", feature = "native-verification")))]
fn main() {
    eprintln!("Build on Windows with --features native-verification");
    std::process::exit(1);
}
