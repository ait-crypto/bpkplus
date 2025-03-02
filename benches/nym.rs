use criterion::{Criterion, black_box, criterion_group, criterion_main};
use nymgen::*;

fn bench_nym(c: &mut Criterion) {
    let pp = PP::default();

    let (msk, mpk) = CentralAuthroitySK::rand(&pp);
    let (_, sppk) = ServiceProviderSK::rand(&pp);
    let (usk, _) = msk.rand_user(&pp);

    c.bench_function("NymGen", |b| {
        b.iter(|| black_box(usk.nymgen(&pp, &sppk, &mpk)))
    });

    let (nym, pi) = usk.nymgen(&pp, &sppk, &mpk);
    c.bench_function("NymVf", |b| {
        b.iter(|| black_box(verify(&pp, &mpk, &sppk, &nym, &pi)))
    });
}

criterion_group!(benches, bench_nym);
criterion_main!(benches);
