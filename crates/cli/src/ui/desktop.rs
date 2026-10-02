//! Structured prompt transport for the desktop's windowless operation runner.
use crate::error::CliError;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

pub const EVENT_PREFIX: &str = "__HC_DESKTOP_EVENT__";
static NEXT_PROMPT: AtomicU64 = AtomicU64::new(1);

pub fn enabled() -> bool {
    std::env::var("HYBRIDCIPHER_DESKTOP_OPERATION").as_deref() == Ok("1")
}
pub fn require_selected_group(group: uuid::Uuid) -> Result<(), CliError> {
    if enabled() {
        let expected = std::env::var("HYBRIDCIPHER_DESKTOP_GROUP")
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(&value).ok());
        if expected != Some(group) {
            return Err(CliError::permission(
                "Group does not match the selected desktop workspace",
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Prompt<'a> {
    event: &'static str,
    id: String,
    kind: &'a str,
    message: &'a str,
    default_value: Option<&'a str>,
}

#[derive(Deserialize)]
struct Answer {
    request_id: String,
    value: Option<String>,
}
impl Drop for Answer {
    fn drop(&mut self) {
        if let Some(value) = &mut self.value {
            value.zeroize();
        }
    }
}

pub fn request(kind: &str, message: &str, default: Option<&str>) -> Result<String, CliError> {
    let id = NEXT_PROMPT.fetch_add(1, Ordering::SeqCst).to_string();
    let prompt = Prompt {
        event: "needs_input",
        id: id.clone(),
        kind,
        message,
        default_value: default,
    };
    let json = serde_json::to_string(&prompt)
        .map_err(|_| CliError::internal("Could not prepare desktop prompt"))?;
    // A dedicated line is parsed by the desktop. User answers are never printed.
    println!("\n{}{}", EVENT_PREFIX, json);
    std::io::stdout()
        .flush()
        .map_err(|_| CliError::internal("Desktop prompt transport closed"))?;
    let mut line = Zeroizing::new(String::new());
    let count = std::io::stdin()
        .lock()
        .take(65_537)
        .read_line(&mut line)
        .map_err(|_| CliError::internal("Desktop input transport closed"))?;
    if count == 0 || line.len() > 65_536 {
        return Err(CliError::invalid_input("Desktop operation cancelled"));
    }
    decode_answer(&line, &id)
}

fn decode_answer(line: &str, id: &str) -> Result<String, CliError> {
    let mut answer: Answer = serde_json::from_str(line)
        .map_err(|_| CliError::invalid_input("Invalid desktop prompt response"))?;
    if answer.request_id != id {
        return Err(CliError::invalid_input("Desktop prompt response is stale"));
    }
    answer
        .value
        .take()
        .ok_or_else(|| CliError::invalid_input("Desktop operation cancelled"))
}

#[cfg(test)]
#[path = "../../tests/ui/test_desktop_transport.rs"]
mod tests;

pub fn confirmation(message: &str, default: bool) -> Result<bool, CliError> {
    let answer = request("confirm", message, Some(if default { "yes" } else { "no" }))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "yes" | "y" | "true"
    ))
}
