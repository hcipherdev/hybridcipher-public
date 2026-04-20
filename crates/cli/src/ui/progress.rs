use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Create a comprehensive progress bar with enhanced styling
pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb.set_message(message.to_string());
    pb
}

/// Update progress with contextual message and performance feedback
pub fn update_progress_with_message(pb: &ProgressBar, pos: u64, message: &str) {
    pb.set_position(pos);
    pb.set_message(message.to_string());
}

/// Create authentication progress spinner with security indicators
pub fn create_auth_progress(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.blue} {elapsed:.dim} 🔐 {msg}")
            .unwrap()
            .tick_strings(&["🔓", "🔒", "🔐", "🔑"]),
    );
    pb.set_message(format!("Auth: {}", message));
    pb.enable_steady_tick(Duration::from_millis(200));
    pb
}

/// Create file operation progress with enhanced file context
pub fn create_file_progress(total: u64, operation: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.cyan} [{elapsed_precise}] 📁 [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
            )
            .unwrap()
            .progress_chars("██▓▒░  "),
    );
    pb.set_message(format!("File {}: Processing...", operation));
    pb.enable_steady_tick(Duration::from_millis(120));
    pb
}

/// Finish progress with success or error indication
pub fn finish_progress_with_result(pb: &ProgressBar, success: bool, message: &str) {
    if success {
        pb.finish_with_message(format!("✅ {}", message));
    } else {
        pb.finish_with_message(format!("❌ {}", message));
    }
}

/// Specialized progress displays for different operations with enhanced context
pub mod display {
    use std::io::{self, Write};

    /// Display migration status with progress indicators
    pub fn display_migration_status(current_epoch: u64, total_epochs: u64, progress: f64) {
        let bar_length = 40;
        let filled = (progress * bar_length as f64) as usize;
        let empty = bar_length - filled;

        print!("\r🔄 Migration: Epoch {}/{} ", current_epoch, total_epochs);
        print!(
            "[{}{}] {:.1}%",
            "█".repeat(filled),
            "░".repeat(empty),
            progress * 100.0
        );

        if progress >= 1.0 {
            println!(" ✅ Complete");
        } else {
            print!(" Processing...");
        }
        io::stdout().flush().unwrap();
    }

    /// Display coverage verification status with security context
    #[allow(dead_code)]
    pub fn display_coverage_status(verified: usize, total: usize, issues: usize) {
        let progress = verified as f64 / total as f64;
        let bar_length = 30;
        let filled = (progress * bar_length as f64) as usize;
        let empty = bar_length - filled;

        print!("\r🔍 Coverage Verification: ");
        print!("[{}{}] ", "✓".repeat(filled), "·".repeat(empty));
        print!("{}/{} files verified", verified, total);

        if issues > 0 {
            print!(" ⚠️  {} issues found", issues);
        }

        if verified == total {
            println!(" ✅ Complete");
        } else {
            print!(" Scanning...");
        }
        io::stdout().flush().unwrap();
    }

    /// Display file operation status with detailed context
    pub fn display_file_status(operation: &str, file_path: &str, status: &str) {
        println!("📁 {}: {} - {}", operation, file_path, status);
    }
}

/// Enhanced progress utilities for CLI operations
pub mod utils {
    use std::time::Duration;

    /// Calculate and display estimated time remaining
    pub fn display_eta(current: u64, total: u64, elapsed: Duration) -> String {
        if current == 0 {
            return "Calculating...".to_string();
        }

        let rate = current as f64 / elapsed.as_secs_f64();
        let remaining = total - current;
        let eta_seconds = remaining as f64 / rate;

        if eta_seconds < 60.0 {
            format!("{:.0}s", eta_seconds)
        } else if eta_seconds < 3600.0 {
            format!("{:.0}m {:.0}s", eta_seconds / 60.0, eta_seconds % 60.0)
        } else {
            format!(
                "{:.0}h {:.0}m",
                eta_seconds / 3600.0,
                (eta_seconds % 3600.0) / 60.0
            )
        }
    }
}
