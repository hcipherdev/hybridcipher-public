//! Opt-in acceptance runner. It only creates disposable synthetic vaults, and
//! runs inside the same desktop executable as the production provider.
use super::*;
use hybridcipher_provider_core::compatibility_fixtures;
use std::{
    os::windows::process::CommandExt,
    process::{Command, Stdio},
};

type CheckResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn require(ok: bool, message: &str) -> CheckResult<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}

pub fn child(args: &[String]) -> CheckResult<()> {
    let operation = args.first().ok_or("missing child operation")?;
    let path = PathBuf::from(args.get(1).ok_or("missing child path")?);
    require(
        path.is_absolute()
            && path
                .ancestors()
                .any(|parent| parent.join(".verification-only").is_file()),
        "child path is outside the disposable verification vault",
    )?;
    match operation.as_str() {
        "read" => {
            let bytes = fs::read(path)?;
            println!("{}:{:x}", bytes.len(), Sha256::digest(&bytes));
        }
        "edit" => fs::write(path, b"intentional native edit")?,
        "atomic-edit" => {
            let temporary = path.with_extension("editor-temporary");
            fs::write(&temporary, b"intentional native atomic edit")?;
            fs::rename(temporary, path)?;
        }
        "rename" => {
            let destination = PathBuf::from(args.get(2).ok_or("missing rename destination")?);
            require(
                path.parent() == destination.parent(),
                "verification rename must stay in its fixture directory",
            )?;
            fs::rename(path, destination)?;
        }
        _ => return Err("unknown verification child operation".into()),
    }
    Ok(())
}

async fn external(
    operation: &str,
    path: &Path,
    destination: Option<&Path>,
) -> CheckResult<std::process::Output> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--native-verification-child")
        .arg(operation)
        .arg(path)
        .creation_flags(0x08000000)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(destination) = destination {
        command.arg(destination);
    }
    Ok(tokio::task::spawn_blocking(move || command.output()).await??)
}

async fn wait_until(mut condition: impl FnMut() -> bool, description: &str) -> CheckResult<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition() {
        if Instant::now() >= deadline {
            return Err(format!("Timed out: {description}").into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn seed_duplicates(
    host: &CloudProviderHost,
    registration: &CloudRootRegistration,
    entry: &ProviderEntry,
    target: &str,
) -> Result<()> {
    let paths = host.runtime_paths(registration.root_id)?;
    let _lease = RootWriterLease::acquire(registration.root_id, &paths.writer_lock_path)?;
    let mut journal = CloudMutationJournal::empty(registration.root_id);
    journal.generation = 1000;
    journal.next_sequence = 122;
    for sequence in 1..=122 {
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            registration.root_id,
            &entry.relative_path,
            Some(entry.identity.clone()),
        );
        record.sequence = sequence;
        record.target_relative_path = Some(target.into());
        record.target_plaintext_path = Some(registration.sync_root_path.join(target));
        record.expected_version = entry.content_version();
        record.attempts = 1;
        record.last_error = Some("legacy missing rename destination".into());
        journal.records.push(record);
    }
    fs::write(&paths.journal_path, journal_schema2::fixture(&journal))?;
    Ok(())
}

pub fn run(base: &Path) -> CheckResult<()> {
    require(
        base.is_absolute() && !base.exists(),
        "verification requires a new absolute directory",
    )?;
    fs::create_dir(base)?;
    fs::write(
        base.join(".verification-only"),
        b"synthetic HybridCipher compatibility acceptance",
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run_async(base));
    let report = match &result {
        Ok(report) => report.clone(),
        Err(error) => serde_json::json!({"passed":false,"error":error.to_string()}),
    };
    fs::write(
        base.join("acceptance.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    result.map(|_| ())
}

async fn run_async(base: &Path) -> CheckResult<serde_json::Value> {
    let root = Uuid::new_v4();
    let group = Uuid::new_v4();
    let account = base
        .join(".hybridcipher")
        .join("users")
        .join("verification");
    let mount = base.join(".hybridcipher").join(format!("{root}_mount"));
    let encrypted = base.join("encrypted");
    fs::create_dir_all(&mount)?;
    fs::create_dir_all(&encrypted)?;
    let client = compatibility_fixtures::client(&account, group).await;
    let policy = Arc::new(VaultCompatibility::load(&account, root)?);
    let bridge = local_provider_bridge_with_compatibility(client.clone(), policy.clone());
    bridge
        .create_directory(root, &encrypted, "API_keys")
        .await?;
    let names = [
        (
            "API_keys/claude  setting.json file using aws platform api.md",
            398,
            2,
            false,
        ),
        ("API_keys/github backup codes.md", 272, 2, false),
        ("sparse-legacy.md", 80, 2, true),
        ("current.md", 192, 3, false),
        ("offline-legacy.md", 64, 2, false),
    ];
    for (name, size, version, sparse) in names {
        compatibility_fixtures::fixture(&encrypted, name, size, version, sparse, group);
    }
    let corrupt_path =
        compatibility_fixtures::fixture(&encrypted, "corrupt-current.md", 144, 3, false, group);
    let mut corrupt_bytes = fs::read(&corrupt_path)?;
    *corrupt_bytes.last_mut().ok_or("empty corrupt fixture")? ^= 1;
    fs::write(&corrupt_path, corrupt_bytes)?;
    let host = CloudProviderHost::with_provider_bridge(
        ProviderHostConfig {
            user_config_dir: account.clone(),
            pipe_name: None,
        },
        bridge.clone(),
    );
    let registration = CloudRootRegistration::legacy_cfapi(
        root,
        mount.clone(),
        encrypted.clone(),
        format!("HybridCipher disposable compatibility verification {root}"),
    );
    host.register_root(&registration)?;
    let result: CheckResult<serde_json::Value> = async {
        fs::write(base.join("phase.txt"), "start-provider").ok();
        host.start_root_with_bridge(root,bridge.clone()).await?;
        require(!external("read",&mount.join(names[0].0),None).await?.status.success(), "legacy read succeeded without acknowledgment")?;
        require(external("read",&mount.join("current.md"),None).await?.status.success(), "current file unavailable after a declined legacy read")?;
        require(host.check_root_health(root)?.operational.is_some_and(|o| o.healthy), "file-level failure damaged provider health")?;
        require(!external("read", &mount.join("corrupt-current.md"), None).await?.status.success(),
            "corrupt version-3 file was accepted")?;
        require(bridge.compatibility_status().and_then(|s| s.last_read_error)
            == Some(hybridcipher_provider_core::ProviderFileErrorCode::IntegrityFailure),
            "integrity failure lost its typed desktop status")?;
        require(external("read", &mount.join("current.md"), None).await?.status.success(),
            "a corrupt file made other files unavailable")?;
        require(host.check_root_health(root)?.operational.is_some_and(|o| o.healthy),
            "integrity failure damaged provider health")?;
        fs::write(base.join("phase.txt"), "acknowledge").ok();
        host.set_legacy_compatibility(root,true).await?;
        let entries=bridge.inventory(root,&encrypted).await?;
        for (name,size,version,sparse) in names.into_iter().filter(|(name,_,_,_)| *name != "offline-legacy.md") {
            let entry=entries.iter().find(|e| e.relative_path==name).ok_or("fixture inventory missing")?;
            let before=fs::read(&entry.encrypted_path)?;
            let direct = host.runtime_paths(root)?.cache_dir.join(".verification-direct.plain.tmp");
            let direct_result = bridge.hydrate_file_to_path(entry, &direct).await;
            let _ = fs::remove_file(&direct);
            direct_result?;
            let output=external("read",&mount.join(name),None).await?;
            require(output.status.success(),&format!("acknowledged read failed: {}",String::from_utf8_lossy(&output.stderr)))?;
            let mut expected=vec![42;size]; if sparse { expected.resize(size+64,0); }
            require(String::from_utf8_lossy(&output.stdout).trim()==format!("{}:{:x}",expected.len(),Sha256::digest(&expected)),"hydrated plaintext mismatch")?;
            require(fs::read(&entry.encrypted_path)?==before,"read-only close changed ciphertext")?;
            let _ = version;
        }
        require(!policy.status().encrypted_backup_directory.exists(),"read-only close created an upgrade backup")?;
        fs::write(base.join("phase.txt"), "duplicate-journal").ok();
        let github=entries.iter().find(|e| e.relative_path==names[1].0).unwrap().clone();
        let target="API_keys/github backup-codes.md";
        host.stop_root_for_restart(root).await?;
        seed_duplicates(&host,&registration,&github,target)?;
        let reloaded=Arc::new(VaultCompatibility::load(&account,root)?); require(reloaded.status().enabled,"acknowledgment was lost on restart")?;
        let bridge=local_provider_bridge_with_compatibility(client,reloaded);
        fs::write(base.join("phase.txt"), "start-provider").ok();
        host.start_root_with_bridge(root,bridge.clone()).await?;
        let pending=host.read_runtime_status(root)?;
        require(pending.pending_operation_count==1 && pending.affected_file_count==1 && pending.pending_operation_counts.get("rename")==Some(&1),"122-record journal did not compact to one rename")?;
        require(mount.join(names[1].0).exists() && !mount.join(target).exists(),"startup automatically moved the original-only rename")?;
        fs::write(base.join("phase.txt"), "keep-original").ok();
        host.resolve_pending_operation(root,pending.pending_operations[0].id,PendingOperationResolution::KeepOriginalName).await?;
        require(host.read_runtime_status(root)?.pending_operation_count==0 && mount.join(names[1].0).exists(),"Keep original name lost content or kept duplicate work")?;
        host.stop_root_for_restart(root).await?;
        seed_duplicates(&host,&registration,&github,target)?;
        fs::write(base.join("phase.txt"), "start-provider").ok();
        host.start_root_with_bridge(root,bridge.clone()).await?;
        let pending=host.read_runtime_status(root)?;
        fs::write(base.join("phase.txt"), "retry-rename").ok();
        host.resolve_pending_operation(root,pending.pending_operations[0].id,PendingOperationResolution::RetryRename).await?;
        require(mount.join(target).exists() && !mount.join(names[1].0).exists(),"Retry rename did not finish the local move")?;
        require(host.read_runtime_status(root)?.pending_operation_count==0,"resolved rename remained pending")?;
        require(external("read",&mount.join(target),None).await?.status.success(),"renamed file cannot be opened")?;
        fs::write(base.join("phase.txt"), "already-committed-rename").ok();
        let committed = bridge.inventory(root, &encrypted).await?.into_iter()
            .find(|e| e.relative_path == target).ok_or("committed target missing")?;
        let committed_ciphertext = fs::read(&committed.encrypted_path)?;
        host.stop_root_for_restart(root).await?;
        {
            let paths = host.runtime_paths(root)?;
            let _lease = RootWriterLease::acquire(root, &paths.writer_lock_path)?;
            let mut journal = parse_mutation_journal(&fs::read(&paths.journal_path)?, root)?;
            let mut record = CloudMutationRecord::new(CloudMutationKind::Rename, root,
                &github.relative_path, Some(github.identity.clone()));
            journal.next_sequence += 1;
            record.sequence = journal.next_sequence;
            record.target_relative_path = Some(target.into());
            record.target_plaintext_path = Some(mount.join(target));
            record.expected_version = github.content_version();
            record.committed_version = committed.content_version();
            journal.records.push(record);
            write_mutation_journal(&paths.journal_path, &journal)?;
        }
        host.start_root_with_bridge(root, bridge.clone()).await?;
        require(host.read_runtime_status(root)?.pending_operation_count == 0,
            "already committed rename did not finish bookkeeping on restart")?;
        require(fs::read(&committed.encrypted_path)? == committed_ciphertext,
            "already committed rename encrypted its contents again")?;
        fs::write(base.join("phase.txt"), "atomic-save").ok();
        let claude=entries.iter().find(|e| e.relative_path==names[0].0).unwrap(); let original=fs::read(&claude.encrypted_path)?;
        require(external("atomic-edit",&mount.join(names[0].0),None).await?.status.success(),"editor atomic save failed")?;
        wait_until(|| hybridcipher_provider_core::EncryptedInventory::new(root,&encrypted).scan().ok().is_some_and(|entries| entries.iter().any(|e| e.relative_path==names[0].0 && e.metadata.as_ref().is_some_and(|m| m.header_version==Some(3)))),"atomic editor save upgrade").await?;
        let backup=policy.status().encrypted_backup_directory.join(format!("{:x}",Sha256::digest(claude.identity.file_id.as_ref().unwrap().as_bytes()))).join(format!("{:x}.encrypted",Sha256::digest(&original)));
        require(fs::read(backup)?==original,"encrypted original backup was not exact")?;
        fs::write(base.join("phase.txt"), "offline-rename").ok();
        require(external("rename",&mount.join("offline-legacy.md"),Some(&mount.join("offline-renamed.md"))).await?.status.success(),"external offline rename failed")?;
        wait_until(|| hybridcipher_provider_core::EncryptedInventory::new(root,&encrypted).scan().ok().is_some_and(|entries| entries.iter().any(|e| e.relative_path=="offline-renamed.md" && e.metadata.as_ref().is_some_and(|m| m.header_version==Some(3)))) && host.read_runtime_status(root).is_ok_and(|s| s.pending_operation_count==0),"offline rename without self-hydration").await?;
        require(host.check_root_health(root)?.operational.is_some_and(|o| o.healthy),"provider health failed during isolated acceptance")?;
        Ok(serde_json::json!({"passed":true,"root_id":root,"legacy_reads":true,"strict_before_consent":true,"current_after_decline":true,"consent_survives_restart":true,"readonly_ciphertext_unchanged":true,"duplicates_before":122,"duplicates_after":1,"both_rename_resolutions":true,"already_committed_rename":true,"atomic_editor_upgrade_and_exact_backup":true,"offline_rename":true,"provider_healthy":true,"corrupt_file_isolated":true}))
    }.await;
    let stopped = host.stop_root_for_restart(root).await;
    let unregistered = if stopped.is_ok() {
        host.unregister_root_path(&mount)
    } else {
        Err(CloudProviderError::Callback(
            "verification provider did not disconnect".into(),
        ))
    };
    stopped?;
    unregistered?;
    result
}
