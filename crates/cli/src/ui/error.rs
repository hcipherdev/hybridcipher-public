use crate::error::CliError;
use console::{style, Term};
use std::time::Duration;

/// Display a detailed error with recovery suggestions and performance context
pub fn display_error_with_context(error: &CliError, execution_time: Duration) {
    let term = Term::stderr();

    // Error header with timing context
    let _ = term.write_line("");
    let _ = term.write_line(&format!(
        "{} {} {}",
        style("✗").red().bold(),
        style("Error:").red().bold(),
        style(error.to_string()).red()
    ));

    // Show execution time for performance context
    if execution_time > Duration::from_millis(100) {
        let _ = term.write_line(&format!(
            "  {} Command failed after {:.2}s",
            style("⏱").dim(),
            execution_time.as_secs_f64()
        ));
    }

    // Recovery suggestions with enhanced formatting
    let suggestions = error.recovery_suggestions();
    if !suggestions.is_empty() {
        let _ = term.write_line("");
        let _ = term.write_line(&format!("{}", style("Possible solutions:").yellow().bold()));

        for (i, suggestion) in suggestions.iter().enumerate() {
            let _ = term.write_line(&format!("  {}. {}", style(i + 1).cyan().bold(), suggestion));
        }
    }

    // Enhanced help section
    let _ = term.write_line("");
    let _ = term.write_line(&format!(
        "{} Use {} for command help",
        style("Tip:").blue().bold(),
        style("hybridcipher help").cyan().underlined()
    ));

    // Debug information in verbose mode
    if std::env::var("HYBRIDCIPHER_VERBOSE").is_ok() {
        let _ = term.write_line("");
        let _ = term.write_line(&format!("{}", style("Debug Information:").dim()));
        let _ = term.write_line(&format!("  Error type: {:?}", error));
        let _ = term.write_line(&format!("  Execution time: {:?}", execution_time));
    }
    let _ = term.write_line("");
}

/// Display CLI usage error with helpful guidance
pub fn display_cli_usage_error(error_message: &str) {
    let term = Term::stderr();

    let _ = term.write_line("");
    let _ = term.write_line(&format!(
        "{} {}",
        style("✗").red().bold(),
        style("Invalid command usage").red().bold()
    ));

    let _ = term.write_line(&format!("  {}", error_message));
    let _ = term.write_line("");

    let _ = term.write_line(&format!("{}", style("Quick help:").blue().bold()));
    let _ = term.write_line("  • Use 'hybridcipher --help' for all available commands");
    let _ = term.write_line("  • Use 'hybridcipher <command> --help' for specific command help");
    let _ = term.write_line("  • Use 'hybridcipher login <username>' to authenticate");
    let _ = term.write_line("");
}
