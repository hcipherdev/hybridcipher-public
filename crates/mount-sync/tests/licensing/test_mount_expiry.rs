// Tests SyncTracker preservation of pending edits at license expiry and retry after restoration.
struct LicenseGateCrypto(std::sync::atomic::AtomicBool);

#[async_trait]
impl MountCrypto for LicenseGateCrypto {
    async fn check_write_access(&self) -> Result<(), MountSyncError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) { Ok(()) }
        else { Err(MountSyncError::Crypto("Team entitlement expired".into())) }
    }
    async fn decrypt_file(&self, path: &Path, metadata: &EncryptedFileMetadata) -> Result<Vec<u8>, MountSyncError> {
        MockCrypto.decrypt_file(path, metadata).await
    }
    async fn decrypt_file_streaming(&self, path: &Path, output: &Path, metadata: &EncryptedFileMetadata) -> Result<(), MountSyncError> {
        MockCrypto.decrypt_file_streaming(path, output, metadata).await
    }
    async fn encrypt_file(&self, path: &str, plaintext: &[u8]) -> Result<EncryptedFileMetadata, MountSyncError> {
        self.check_write_access().await?; MockCrypto.encrypt_file(path, plaintext).await
    }
    async fn encrypt_file_with_id(&self, path: &str, plaintext: &[u8], id: &str) -> Result<EncryptedFileMetadata, MountSyncError> {
        self.check_write_access().await?; MockCrypto.encrypt_file_with_id(path, plaintext, id).await
    }
    async fn encrypt_file_streaming(&self, path: &str, plaintext: &Path, output: &Path, name: Option<&str>, metadata: Option<&PlatformFileMetadata>, chunks: usize) -> Result<StreamingEncryptedFile, MountSyncError> {
        self.check_write_access().await?; MockCrypto.encrypt_file_streaming(path, plaintext, output, name, metadata, chunks).await
    }
    async fn encrypt_file_streaming_with_id(&self, path: &str, plaintext: &Path, output: &Path, name: Option<&str>, metadata: Option<&PlatformFileMetadata>, id: &str, chunks: usize) -> Result<StreamingEncryptedFile, MountSyncError> {
        self.check_write_access().await?; MockCrypto.encrypt_file_streaming_with_id(path, plaintext, output, name, metadata, id, chunks).await
    }
    async fn coverage_store_metadata(&self, metadata: FileMetadataData) -> Result<(), MountSyncError> {
        self.check_write_access().await?; MockCrypto.coverage_store_metadata(metadata).await
    }
}

#[tokio::test]
async fn test_team_mount_expiry_preserves_pending_edits_and_resumes() {
    let temp = TempDir::new().unwrap();
    let encrypted = temp.path().join("encrypted"); let view = temp.path().join("view");
    fs::create_dir(&encrypted).unwrap(); fs::create_dir(&view).unwrap();
    let file = view.join("document.txt"); let ciphertext = encrypted.join("document.txt.encrypted");
    fs::write(&file, b"pending local edit").unwrap();
    write_file_id_xattr(&file, "file-1").unwrap();
    write_test_encrypted_file(&ciphertext, "file-1", "document.txt").unwrap();
    let original = fs::read(&ciphertext).unwrap();
    let journal = temp.path().join("pending.json");
    let mut tracker = mock_tracker(); tracker.set_pending_writeback_path(journal.clone());
    tracker.seed_file(ciphertext.clone(), file.clone(), test_file_signature(&ciphertext), ZERO_SIGNATURE);
    tracker.file_id_to_mount_path.insert("file-1".into(), file.clone());
    tracker.record_pending_writeback(&file, &ciphertext, None);
    tracker.pending_stable.insert(file.clone(), StableEntry { signature: FileSignature::from_metadata(&fs::metadata(&file).unwrap()), first_seen: Instant::now() - Duration::from_secs(2) });
    let crypto = LicenseGateCrypto(std::sync::atomic::AtomicBool::new(false));
    tracker.sync(&crypto, &encrypted, &view).await.unwrap();
    tracker.retry_pending_writebacks_before_scan(&crypto, &encrypted, &view).await.unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"pending local edit");
    assert_eq!(fs::read(&ciphertext).unwrap(), original);
    assert!(tracker.pending_writebacks.contains_key(&file));
    assert!(journal.exists());
    assert!(fs::write(&file, b"blocked").is_err());
    crypto.0.store(true, std::sync::atomic::Ordering::SeqCst);
    tracker.sync(&crypto, &encrypted, &view).await.unwrap();
    // Restoring Windows ACLs changes the signature; the next stable scan commits.
    tracker.sync(&crypto, &encrypted, &view).await.unwrap();
    tracker.retry_pending_writebacks_before_scan(&crypto, &encrypted, &view).await.unwrap();
    assert!(!tracker.pending_writebacks.contains_key(&file), "pending={:?}; stable={:?}; denied={:?}; age={}; readonly={}; health={:?}", tracker.pending_writebacks.get(&file), tracker.pending_stable.get(&file), tracker.write_access_denied, tracker.stream_stability_age_secs, tracker.mount_readonly_active, tracker.scan_health);
    assert_ne!(fs::read(&ciphertext).unwrap(), original);
    fs::write(&file, b"restored write access").unwrap();
}

#[tokio::test]
async fn test_streaming_stability_timer_survives_frequent_scans() {
    let temp = TempDir::new().unwrap();
    let encrypted = temp.path().join("encrypted"); let view = temp.path().join("view");
    fs::create_dir(&encrypted).unwrap(); fs::create_dir(&view).unwrap();
    let file = view.join("document.txt"); fs::write(&file, b"stable local edit").unwrap();
    let first_seen = Instant::now() - Duration::from_secs(2);
    let mut tracker = SyncTracker::new();
    tracker.pending_stable.insert(file.clone(), StableEntry { signature: test_file_signature(&file), first_seen });
    tracker.sync_decrypted_changes(&MockCrypto, &encrypted, &view, &mut HashSet::new(), &HashSet::new()).await.unwrap();
    assert_eq!(tracker.pending_stable[&file].first_seen, first_seen);
    assert!(!encrypted.join("document.txt.encrypted").exists());
}
