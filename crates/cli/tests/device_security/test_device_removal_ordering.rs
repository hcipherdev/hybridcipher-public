// Verify self-removal authorization and safe shutdown complete before a DELETE can run.
use super::*;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn authorization_failure_never_stops_mounts_or_sends_delete() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let result = authorize_and_prepare_device_removal(
        async {
            events.lock().unwrap().push("authorize");
            Err::<(), _>(CliError::authentication("rejected"))
        },
        true,
        async {
            events.lock().unwrap().push("stop");
            Ok(())
        },
    )
    .await;
    if result.is_ok() {
        events.lock().unwrap().push("delete");
    }
    assert!(result.is_err());
    assert_eq!(*events.lock().unwrap(), vec!["authorize"]);
}

#[tokio::test]
async fn unsafe_shutdown_preserves_authorization_and_never_sends_delete() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let result = authorize_and_prepare_device_removal(
        async {
            events.lock().unwrap().push("authorize");
            Ok(())
        },
        true,
        async {
            events.lock().unwrap().push("stop");
            Err(CliError::mount("pending writes"))
        },
    )
    .await;
    if result.is_ok() {
        events.lock().unwrap().push("delete");
    }
    assert!(result.is_err());
    assert_eq!(*events.lock().unwrap(), vec!["authorize", "stop"]);
}

#[tokio::test]
async fn successful_self_removal_stops_mounts_before_delete_and_other_removal_does_not() {
    for removing_self in [true, false] {
        let events = Arc::new(Mutex::new(Vec::new()));
        authorize_and_prepare_device_removal(
            async {
                events.lock().unwrap().push("authorize");
                Ok(())
            },
            removing_self,
            async {
                events.lock().unwrap().push("stop");
                Ok(())
            },
        )
        .await
        .unwrap();
        events.lock().unwrap().push("delete");
        assert_eq!(
            *events.lock().unwrap(),
            if removing_self {
                vec!["authorize", "stop", "delete"]
            } else {
                vec!["authorize", "delete"]
            }
        );
    }
}
