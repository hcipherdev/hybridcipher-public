//! The installer may terminate Windows immediately: all cleanup is a prerequisite.
use std::future::Future;
use tokio::sync::RwLock;

pub(super) async fn install<T>(
    gate: &RwLock<()>,
    stop_cloud_roots: impl Future<Output = Result<(), String>>,
    unmount: impl Future<Output = Result<(), String>>,
    install: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let _exclusive = gate.write().await;
    stop_cloud_roots.await?;
    unmount.await?;
    install()
}

#[cfg(test)]
mod security_regression {
    use super::*;
    use std::sync::Mutex;
    #[tokio::test]
    async fn installer_runs_only_after_both_cleanup_steps_and_excludes_operations() {
        let gate = RwLock::new(());
        let steps = Mutex::new(Vec::new());
        install(
            &gate,
            async {
                steps.lock().unwrap().push("cloud");
                Ok(())
            },
            async {
                steps.lock().unwrap().push("mounts");
                Ok(())
            },
            || {
                assert!(gate.try_read().is_err());
                steps.lock().unwrap().push("install");
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(*steps.lock().unwrap(), ["cloud", "mounts", "install"]);
        assert!(gate.try_read().is_ok());
    }
    #[tokio::test]
    async fn every_cleanup_failure_prevents_installation_and_releases_gate() {
        for cloud_fails in [true, false] {
            let gate = RwLock::new(());
            let result = install(
                &gate,
                async {
                    if cloud_fails {
                        Err("pending cloud write".into())
                    } else {
                        Ok(())
                    }
                },
                async { Err("pending mount write".into()) },
                || -> Result<(), String> { panic!("Installer must not run") },
            )
            .await;
            assert!(result.is_err());
            assert!(gate.try_read().is_ok());
        }
    }
    #[tokio::test]
    async fn update_waits_for_an_existing_operation() {
        let gate = RwLock::new(());
        let operation = gate.read().await;
        let mut update = std::pin::pin!(install(&gate, async { Ok(()) }, async { Ok(()) }, || Ok(
            ()
        )));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut update)
                .await
                .is_err()
        );
        drop(operation);
        update.await.unwrap();
    }
}
