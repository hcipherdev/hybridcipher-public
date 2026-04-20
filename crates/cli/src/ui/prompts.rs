use crate::error::CliError;
use console::style;
use dialoguer::{Confirm, Input, Password};

/// Prompt for user confirmation with yes/no
pub fn confirm(message: &str) -> Result<bool, CliError> {
    Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()
        .map_err(|e| CliError::internal(format!("Failed to get user confirmation: {}", e)))
}

/// Prompt for user confirmation with custom default
pub fn confirm_with_default(message: &str, default: bool) -> Result<bool, CliError> {
    Confirm::new()
        .with_prompt(message)
        .default(default)
        .interact()
        .map_err(|e| CliError::internal(format!("Failed to get user confirmation: {}", e)))
}

/// Prompt for text input
pub fn input(message: &str) -> Result<String, CliError> {
    Input::new()
        .with_prompt(message)
        .interact_text()
        .map_err(|e| CliError::internal(format!("Failed to get user input: {}", e)))
}

/// Prompt for text input with default value
pub fn input_with_default(message: &str, default: &str) -> Result<String, CliError> {
    Input::new()
        .with_prompt(message)
        .default(default.to_string())
        .interact_text()
        .map_err(|e| CliError::internal(format!("Failed to get user input: {}", e)))
}

/// Prompt for optional text input (allows empty to be submitted)
pub fn input_allow_empty(message: &str) -> Result<String, CliError> {
    Input::new()
        .with_prompt(message)
        .allow_empty(true)
        .interact_text()
        .map_err(|e| CliError::internal(format!("Failed to get user input: {}", e)))
}

/// Prompt for password input
pub fn password(message: &str) -> Result<String, CliError> {
    Password::new()
        .with_prompt(message)
        .interact()
        .map_err(|e| CliError::internal(format!("Failed to get password: {}", e)))
}

/// Prompt for password input with confirmation
pub fn password_with_confirmation(message: &str) -> Result<String, CliError> {
    Password::new()
        .with_prompt(message)
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()
        .map_err(|e| CliError::internal(format!("Failed to get password: {}", e)))
}

/// Display a warning prompt for destructive operations
pub fn destructive_operation_warning(
    operation: &str,
    consequences: &[&str],
    confirmation_text: &str,
) -> Result<bool, CliError> {
    println!();
    println!(
        "{}",
        style("⚠️  WARNING: Destructive Operation").red().bold()
    );
    println!("{}", style(format!("Operation: {}", operation)).yellow());
    println!();
    println!("{}", style("This operation will:").bold());
    for consequence in consequences {
        println!("  {} {}", style("•").red(), consequence);
    }
    println!();
    println!("{}", style("This action cannot be undone!").red().bold());
    println!();

    let input: String = Input::new()
        .with_prompt(format!("Type '{}' to confirm", confirmation_text))
        .interact_text()
        .map_err(|e| CliError::internal(format!("Failed to get confirmation: {}", e)))?;

    Ok(input == confirmation_text)
}

/// Display migration impact warning
#[allow(dead_code)]
pub fn migration_impact_warning(
    current_epoch: u64,
    target_epoch: u64,
    affected_files: usize,
) -> Result<bool, CliError> {
    migration_impact_warning_with_coverage(current_epoch, target_epoch, affected_files, None)
}

/// Display migration impact warning with optional coverage percentage
pub fn migration_impact_warning_with_coverage(
    current_epoch: u64,
    target_epoch: u64,
    affected_files: usize,
    coverage_info: Option<(usize, usize, usize)>, // (tracked, orphaned, unmanaged)
) -> Result<bool, CliError> {
    println!();
    println!("{}", style("🔄 Migration Impact Summary").cyan().bold());
    println!(
        "{}",
        style(format!(
            "Epoch transition: {} → {}",
            current_epoch, target_epoch
        ))
        .yellow()
    );
    println!(
        "{}",
        style(format!("Files to migrate: {}", affected_files)).yellow()
    );

    // Display coverage percentage if available
    if let Some((tracked, orphaned, unmanaged)) = coverage_info {
        let total = tracked + orphaned + unmanaged;
        if total > 0 {
            let percentage = (tracked as f64 / total as f64) * 100.0;
            let coverage_str = format!(
                "Coverage tracked: {:.1}% ({}/{})",
                percentage, tracked, total
            );

            if percentage >= 95.0 {
                println!("{}", style(coverage_str).green());
            } else {
                println!("{}", style(coverage_str).yellow());
                println!();
                println!("{}", style("⚠ Warning: Coverage below 95%").yellow().bold());
                println!(
                    "{}",
                    style(format!(
                        "  {} orphaned file(s), {} unmanaged file(s) detected",
                        orphaned, unmanaged
                    ))
                    .yellow()
                );
                println!(
                    "{}",
                    style("  Run 'hybridcipher coverage scan' followed by 'hybridcipher coverage status'").dim()
                );
                println!(
                    "{}",
                    style("  to review and resolve untracked files before starting rekey.").dim()
                );
            }
        }
    }

    println!();
    println!("{}", style("During migration:").bold());
    println!("  {} File access is not affected", style("•").yellow());
    println!(
        "  {} Other group members will be notified",
        style("•").yellow()
    );
    println!(
        "  {} Migration can be monitored with 'hybridcipher rekey status'",
        style("•").yellow()
    );
    println!();

    confirm("Do you want to proceed with the migration to a new epoch key?")
}
