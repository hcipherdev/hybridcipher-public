use criterion::{criterion_group, criterion_main, Criterion};

fn crypto_benchmarks(_c: &mut Criterion) {
    // Placeholder benchmarks - will be implemented as crypto functions are added
}

criterion_group!(benches, crypto_benchmarks);
criterion_main!(benches);
