use console::Style;

pub mod error;
pub mod formatting;
pub mod progress;
pub mod prompts;

/// UI style constants for consistent formatting
pub struct Styles {
    pub success: Style,
    pub error: Style,
    pub warning: Style,
    pub info: Style,
    pub highlight: Style,
    pub dim: Style,
    pub bold: Style,
}

impl Default for Styles {
    fn default() -> Self {
        Self {
            success: Style::new().green().bold(),
            error: Style::new().red().bold(),
            warning: Style::new().yellow().bold(),
            info: Style::new().blue().bold(),
            highlight: Style::new().cyan().bold(),
            dim: Style::new().dim(),
            bold: Style::new().bold(),
        }
    }
}

/// Global UI styles instance
pub static STYLES: once_cell::sync::Lazy<Styles> = once_cell::sync::Lazy::new(Styles::default);

/// Print a success message
pub fn success(message: &str) {
    println!("{} {}", STYLES.success.apply_to("✓"), message);
}

/// Print an error message
pub fn error(message: &str) {
    eprintln!("{} {}", STYLES.error.apply_to("✗"), message);
}

/// Print a warning message
pub fn warning(message: &str) {
    println!("{} {}", STYLES.warning.apply_to("⚠"), message);
}

/// Print an info message
pub fn info(message: &str) {
    println!("{} {}", STYLES.info.apply_to("ℹ"), message);
}

/// Print a highlighted message
pub fn highlight(message: &str) {
    println!("{}", STYLES.highlight.apply_to(message));
}

/// Print a dimmed message
pub fn dim(message: &str) {
    println!("{}", STYLES.dim.apply_to(message));
}

/// Print a section header
pub fn section(title: &str) {
    println!();
    println!("{}", STYLES.bold.apply_to(format!("=== {} ===", title)));
    println!();
}

/// Print a subsection header
pub fn subsection(title: &str) {
    println!("{}", STYLES.bold.apply_to(format!("--- {} ---", title)));
}
