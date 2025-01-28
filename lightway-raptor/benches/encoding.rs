use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::Rng;
use raptorq::Encoder;

fn criterion_benchmark(c: &mut Criterion) {
    // Parameters for Raptor
    let num_of_repair_symbols = 5;

    // Size of a packet in the frame
    let mtu = 1400;

    let mut group = c.benchmark_group("Raptor");

    for data_size in (1..20480).step_by(1024) {
        let mut data: Vec<u8> = vec![0; data_size];
        for i in 0..data.len() {
            data[i] = rand::rng().random();
        }

        let parameters = data_size;
        group.bench_with_input(BenchmarkId::new("DataSizeInBytes", parameters), &parameters, |bencher, _param| bencher.iter(|| {
            let encoder = Encoder::with_defaults(&data, mtu as u16);
            let _encoded_symbols: Vec<Vec<u8>> = encoder
            .get_encoded_packets(num_of_repair_symbols)
            .iter()
            .map(|sym| sym.serialize())
            .collect();
        }));
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
