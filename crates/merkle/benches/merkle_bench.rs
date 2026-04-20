use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hybridcipher_merkle::MerkleTree;

fn bench_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_construction");

    for size in [100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("from_scratch", size), size, |b, &size| {
            b.iter(|| {
                let mut tree = MerkleTree::new();
                for i in 0..size {
                    tree.insert_leaf(black_box(format!("leaf {}", i).as_bytes()));
                }
                black_box(tree.root())
            });
        });

        group.bench_with_input(BenchmarkId::new("batch_insert", size), size, |b, &size| {
            b.iter(|| {
                let data: Vec<Vec<u8>> = (0..size)
                    .map(|i| format!("leaf {}", i).into_bytes())
                    .collect();
                let data_refs: Vec<&[u8]> = data.iter().map(|x| x.as_slice()).collect();

                let mut tree = MerkleTree::new();
                tree.insert_leaves(black_box(&data_refs));
                black_box(tree.root())
            });
        });
    }
    group.finish();
}

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");

    for size in [1000, 10000].iter() {
        // Pre-build tree
        let mut tree = MerkleTree::new();
        for i in 0..*size {
            tree.insert_leaf(format!("leaf {}", i).as_bytes());
        }

        group.bench_with_input(BenchmarkId::new("single_proof", size), size, |b, &size| {
            b.iter(|| {
                let index = black_box(size / 2); // Middle leaf
                black_box(tree.generate_proof(index))
            });
        });

        group.bench_with_input(BenchmarkId::new("batch_proofs", size), size, |b, &size| {
            b.iter(|| {
                let indices = black_box(vec![0, size / 4, size / 2, 3 * size / 4, size - 1]);
                let mut proofs = Vec::new();
                for index in indices {
                    proofs.push(tree.generate_proof(index).unwrap());
                }
                black_box(proofs)
            });
        });
    }
    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");

    // Build test tree
    let mut tree = MerkleTree::new();
    let test_data: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("leaf {}", i).into_bytes())
        .collect();

    for data in &test_data {
        tree.insert_leaf(data);
    }

    let root = tree.root().unwrap();

    // Generate some proofs
    let proofs: Vec<_> = (0..10)
        .map(|i| {
            let index = i * 100;
            let proof = tree.generate_proof(index).unwrap();
            (proof, test_data[index].as_slice())
        })
        .collect();

    group.bench_function("single_verify", |b| {
        b.iter(|| {
            let (proof, data) = black_box(&proofs[0]);
            black_box(proof.verify(&root, data))
        });
    });

    group.bench_function("batch_verify", |b| {
        b.iter(|| black_box(tree.batch_verify(black_box(&proofs))));
    });

    group.finish();
}

fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");

    for size in [1000, 10000, 100000].iter() {
        group.bench_with_input(BenchmarkId::new("memory_usage", size), size, |b, &size| {
            b.iter(|| {
                let mut tree = MerkleTree::new();
                for i in 0..size {
                    tree.insert_leaf(format!("leaf {}", i).as_bytes());
                }
                black_box(tree.memory_usage())
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_tree_construction,
    bench_proof_generation,
    bench_proof_verification,
    bench_memory_efficiency
);
criterion_main!(benches);
