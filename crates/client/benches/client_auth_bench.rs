use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hybridcipher_client::{
    auth::{LoginFlow, RegistrationFlow},
    network::MockNetwork,
    storage::MockStorage,
};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("opaque_registration", |b| {
        b.iter(|| {
            rt.block_on(async {
                let storage = Arc::new(MockStorage::new());
                let mut registration = RegistrationFlow::new("bench-device".to_string(), storage);

                let result = registration
                    .register(black_box("benchmark-password"), black_box([0x42u8; 32]))
                    .await;

                black_box(result.unwrap());
            });
        });
    });
}

fn bench_login(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Pre-register a user for login benchmarks
    let (storage, registration_record) = rt.block_on(async {
        let storage = Arc::new(MockStorage::new());
        let mut registration = RegistrationFlow::new("bench-device".to_string(), storage.clone());

        let result = registration
            .register("benchmark-password", [0x42u8; 32])
            .await
            .unwrap();
        (storage, result.registration_record)
    });

    c.bench_function("opaque_login", |b| {
        b.iter(|| {
            rt.block_on(async {
                let login = LoginFlow::new("bench-device".to_string(), storage.clone());
                let result = login
                    .login(
                        black_box("benchmark-password"),
                        black_box(&registration_record),
                    )
                    .await;

                black_box(result.unwrap());
            });
        });
    });
}

fn bench_client_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("client_state_operations", |b| {
        b.iter(|| {
            rt.block_on(async {
                let device_identity = Ed25519KeyPair::generate();
                let storage = Arc::new(MockStorage::new());
                let network = Arc::new(MockNetwork::new());

                let client = hybridcipher_client::Client::new(device_identity, storage, network);

                // Benchmark common operations
                let _epoch = client.current_epoch().await;
                let _migrating = client.is_migrating().await;
                let _progress = client.migration_progress().await;
                let _public_key = client.device_public_key();

                client.validate_state().await.unwrap();

                black_box(());
            });
        });
    });
}

fn bench_storage_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("storage_batch_operations", |b| {
        b.iter(|| {
            rt.block_on(async {
                let storage = Arc::new(MockStorage::new());

                // Benchmark batch file metadata storage
                let mut metadata_batch = std::collections::HashMap::new();
                for i in 0..100 {
                    let file_path = format!("/test/file_{}.txt", i);
                    let metadata = hybridcipher_client::FileMetadataData {
                        file_path: file_path.clone(),
                        file_id: Some(file_path.clone()),
                        group_id: Some(Uuid::nil()),
                        epoch_id: 1,
                        header_version: Some(1),
                        wrapped_file_key: None,
                        key_wrap_nonce: None,
                        key_wrap_aad_hash: None,
                        content_nonce: None,
                        content_chunk_size: None,
                        algorithm: "ChaCha20-Poly1305".to_string(),
                        file_size: 1024 * i as u64,
                        modified_at: chrono::Utc::now(),
                        integrity_hash: [i as u8; 32],
                        permissions: hybridcipher_client::AccessControlData {
                            readers: vec![[1u8; 32]],
                            writers: vec![[1u8; 32]],
                            is_public: false,
                        },
                        version: 1,
                        chunks: Vec::new(),
                        encrypted_size: 1024 * i as u64,
                        encrypted_at: chrono::Utc::now(),
                    };
                    metadata_batch.insert(file_path, metadata);
                }

                storage
                    .store_file_metadata_batch(&metadata_batch)
                    .await
                    .unwrap();

                black_box(());
            });
        });
    });
}

criterion_group!(
    benches,
    bench_registration,
    bench_login,
    bench_client_operations,
    bench_storage_operations
);
criterion_main!(benches);
