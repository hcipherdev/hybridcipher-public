// Verify desktop input transport preserves secrets without echo and rejects stale/cancelled replies.
use super::*;

#[test]
fn response_is_bound_to_the_active_prompt() {
    assert!(decode_answer(r#"{"request_id":"old","value":"secret"}"#, "current").is_err());
    assert_eq!(
        decode_answer(r#"{"request_id":"current","value":"secret"}"#, "current").unwrap(),
        "secret"
    );
}
#[test]
fn cancellation_and_malformed_response_fail_closed() {
    assert!(decode_answer(r#"{"request_id":"1","value":null}"#, "1").is_err());
    assert!(decode_answer("password typed as plain text", "1").is_err());
}
#[test]
fn secret_response_is_absent_from_the_prompt_record() {
    let prompt = Prompt {
        event: "needs_input",
        id: "1".into(),
        kind: "password",
        message: "Enter account password",
        default_value: None,
    };
    let serialized = serde_json::to_string(&prompt).unwrap();
    assert!(!serialized.contains("\"value\":"));
    assert!(serialized.contains("password"));
    let answer = "secret with \"quotes\", \\ paths and Unicode 密碼";
    let response = serde_json::json!({"request_id":"1","value":answer}).to_string();
    assert_eq!(decode_answer(&response, "1").unwrap(), answer);
}
