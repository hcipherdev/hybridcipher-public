use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminalDiagnosticPayload {
    pub tab_id: u32,
    pub session_id: Option<String>,
    pub event: String,
    pub textarea_is_active: bool,
    pub xterm_has_focus_class: bool,
    pub rows: Option<u16>,
    pub cols: Option<u16>,
    pub host_visible: bool,
    pub host_width: Option<u32>,
    pub host_height: Option<u32>,
    pub host_occluded: Option<bool>,
    pub occluding_element_tag: Option<String>,
    pub occluding_element_id: Option<String>,
    pub selection_overlay_count: u32,
    pub term_has_selection: bool,
    pub selection_text_length: usize,
    pub active_element_tag: Option<String>,
    pub active_element_id: Option<String>,
}

impl TerminalDiagnosticPayload {
    pub fn normalized(payload: Self) -> Self {
        Self {
            session_id: normalize_optional(payload.session_id, 96),
            event: normalize_required(payload.event, 64, "unknown"),
            occluding_element_tag: normalize_optional(payload.occluding_element_tag, 32),
            occluding_element_id: normalize_optional(payload.occluding_element_id, 64),
            active_element_tag: normalize_optional(payload.active_element_tag, 32),
            active_element_id: normalize_optional(payload.active_element_id, 64),
            ..payload
        }
    }
}

fn normalize_optional(value: Option<String>, max_len: usize) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.chars().take(max_len).collect())
        }
    })
}

fn normalize_required(value: String, max_len: usize, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(max_len).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::TerminalDiagnosticPayload;

    #[test]
    fn terminal_diagnostic_payload_normalizes_large_fields() {
        let payload = TerminalDiagnosticPayload::normalized(TerminalDiagnosticPayload {
            tab_id: 9,
            session_id: Some("s".repeat(200)),
            event: "e".repeat(200),
            textarea_is_active: true,
            xterm_has_focus_class: false,
            rows: Some(32),
            cols: Some(120),
            host_visible: true,
            host_width: Some(640),
            host_height: Some(360),
            host_occluded: Some(true),
            occluding_element_tag: Some("section".repeat(20)),
            occluding_element_id: Some("overlay".repeat(20)),
            selection_overlay_count: 1,
            term_has_selection: false,
            selection_text_length: 0,
            active_element_tag: Some("div".repeat(50)),
            active_element_id: Some("id".repeat(80)),
        });

        assert!(payload.session_id.unwrap().len() <= 96);
        assert!(payload.event.len() <= 64);
        assert!(payload.occluding_element_tag.unwrap().len() <= 32);
        assert!(payload.occluding_element_id.unwrap().len() <= 64);
        assert!(payload.active_element_tag.unwrap().len() <= 32);
        assert!(payload.active_element_id.unwrap().len() <= 64);
    }
}
