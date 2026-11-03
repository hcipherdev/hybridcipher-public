//! Parsing for the embedded HybridCipher console. A typed line only ever becomes
//! arguments to the bundled `hybridcipher` binary: no shell parses it, so pipes,
//! `;`, `&&`, `$(...)` and redirects are plain argument text.

#[cfg(test)]
#[path = "../../tests/operations/test_cli_terminal.rs"]
mod tests;

pub(crate) const NON_CLI_COMMAND_MESSAGE: &str =
    "Only hybridcipher commands run here. Use your system terminal for anything else.";

/// Split a console line into arguments. Whitespace separates arguments; `"..."` and
/// `'...'` group text containing spaces. Backslashes are literal so Windows paths
/// survive unchanged.
pub(crate) fn tokenize_cli_line(line: &str) -> Result<Vec<String>, String> {
    if line.chars().any(|ch| ch.is_control() && ch != '\t') {
        return Err("The command contains control characters".to_string());
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_token = false;
    let mut quote: Option<char> = None;

    for ch in line.chars() {
        match quote {
            Some(open) if ch == open => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                in_token = true;
            }
            None if ch.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut current));
                    in_token = false;
                }
            }
            None => {
                current.push(ch);
                in_token = true;
            }
        }
    }

    if quote.is_some() {
        return Err("The command has an unterminated quote".to_string());
    }
    if in_token {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Turn console tokens into CLI arguments. A leading bare `hybridcipher` (or
/// `hybridcipher.exe`) is optional; any other program name or path is refused.
pub(crate) fn cli_args_from_tokens(mut tokens: Vec<String>) -> Result<Vec<String>, String> {
    let Some(first) = tokens.first() else {
        return Err("Type a hybridcipher command, for example `status` or `help`".to_string());
    };

    if first.contains(['/', '\\']) {
        return Err(NON_CLI_COMMAND_MESSAGE.to_string());
    }
    let lower = first.to_ascii_lowercase();
    if lower == "hybridcipher" || lower == "hybridcipher.exe" {
        tokens.remove(0);
        if tokens.is_empty() {
            return Ok(vec!["--help".to_string()]);
        }
    } else if !first
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        // Subcommands are plain words such as `status` or `add-member`.
        return Err(NON_CLI_COMMAND_MESSAGE.to_string());
    }

    Ok(tokens)
}

/// Parse a console line into arguments for the bundled CLI.
pub(crate) fn parse_cli_line(line: &str) -> Result<Vec<String>, String> {
    cli_args_from_tokens(tokenize_cli_line(line)?)
}
