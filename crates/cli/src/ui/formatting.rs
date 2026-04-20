use console::{style, Style};

/// Format a table with headers and rows
pub fn format_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = String::new();

    // Calculate column widths
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Format header
    let header_style = Style::new().bold();
    output.push_str(&format_row(headers, &widths, &header_style));
    output.push('\n');

    // Add separator
    let separator: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
    output.push_str(&format_row(
        &separator.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &widths,
        &Style::new(),
    ));
    output.push('\n');

    // Format rows
    for row in rows {
        let row_str: Vec<&str> = row.iter().map(|s| s.as_str()).collect();
        output.push_str(&format_row(&row_str, &widths, &Style::new()));
        output.push('\n');
    }

    output
}

fn format_row(cells: &[&str], widths: &[usize], style: &Style) -> String {
    cells
        .iter()
        .zip(widths.iter())
        .map(|(cell, width)| format!("{:<width$}", style.apply_to(cell), width = width))
        .collect::<Vec<_>>()
        .join(" │ ")
}

/// Format a progress percentage with color coding
pub fn format_progress(progress: f64) -> String {
    let progress_str = format!("{:.1}%", progress);
    if progress >= 100.0 {
        style(progress_str).green().to_string()
    } else if progress >= 75.0 {
        style(progress_str).yellow().to_string()
    } else if progress >= 50.0 {
        style(progress_str).cyan().to_string()
    } else {
        style(progress_str).red().to_string()
    }
}

/// Format a file size in human-readable format
pub fn format_file_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format a duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format a timestamp in user-friendly format
pub fn format_timestamp(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let diff = now.signed_duration_since(*timestamp);

    if diff.num_days() > 0 {
        format!("{} days ago", diff.num_days())
    } else if diff.num_hours() > 0 {
        format!("{} hours ago", diff.num_hours())
    } else if diff.num_minutes() > 0 {
        format!("{} minutes ago", diff.num_minutes())
    } else {
        "Just now".to_string()
    }
}

/// Format a timestamp in local time with UTC offset (e.g., 2026-02-05 09:30:00 UTC+01:00).
pub fn format_local_datetime(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    let local = timestamp.with_timezone(&chrono::Local);
    let offset = local.format("%:z");
    format!("{} UTC{}", local.format("%Y-%m-%d %H:%M:%S"), offset)
}

/// Format a timestamp in local time with a relative suffix.
pub fn format_local_datetime_with_relative(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{} ({})",
        format_local_datetime(timestamp),
        format_timestamp(timestamp)
    )
}

/// Format a timestamp in local time and include the UTC time for audit/security logs.
pub fn format_local_and_utc(timestamp: &chrono::DateTime<chrono::Utc>) -> String {
    format!(
        "{} ({})",
        format_local_datetime(timestamp),
        timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    )
}
