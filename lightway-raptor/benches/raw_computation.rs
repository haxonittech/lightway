use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{prelude::SliceRandom, Rng};
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

const NUM_OF_REPAIR_SYMBOLS: u32 = 5; // Number of repair symbols per encode
const MTU: u16 = 1400; // Size of a packet
const DATA_SIZE_STEP: usize = 1024;
const MAX_DATA_SIZE: usize = 20480;

fn bench_encoding(c: &mut Criterion) {
    for data_size in (1..MAX_DATA_SIZE).step_by(DATA_SIZE_STEP) {
        // Generate random packets
        let mut data: Vec<u8> = vec![0; data_size];
        for i in 0..data.len() {
            data[i] = rand::rng().random();
        }

        let parameters = data_size;
        let mut group = c.benchmark_group("Encoding");
        group.bench_with_input(
            BenchmarkId::new("Data size in bytes", parameters),
            &parameters,
            |bencher, _param| {
                bencher.iter(|| {
                    encode(&data, MTU, NUM_OF_REPAIR_SYMBOLS);
                })
            },
        );
        group.finish();
    }
}

fn bench_decoding(c: &mut Criterion) {
    for data_size in (1..MAX_DATA_SIZE).step_by(DATA_SIZE_STEP) {
        // Generate random packets
        let mut data: Vec<u8> = vec![0; data_size];
        for i in 0..data.len() {
            data[i] = rand::rng().random();
        }

        let mut group = c.benchmark_group("Decoding");
        let (mut encoded_symbols, config) = encode(&data, MTU, NUM_OF_REPAIR_SYMBOLS);

        // ~~ OVER ~~ THE ~~ INTERNET ~~ //
        encoded_symbols.shuffle(&mut rand::rng());
        encoded_symbols.truncate(encoded_symbols.len() - NUM_OF_REPAIR_SYMBOLS as usize); // Drop packets at random
                                                                                          // ~~ OVER ~~ THE ~~ INTERNET ~~ //

        let parameters = data_size;
        group.bench_with_input(
            BenchmarkId::new("Data size in bytes", parameters),
            &parameters,
            |bencher, _param| {
                bencher.iter(|| {
                    let mut decoder = Decoder::new(config);
                    for symbol in &encoded_symbols {
                        if let Some(_data) = decoder.decode(EncodingPacket::deserialize(&symbol)) {
                            return;
                        }
                    }
                })
            },
        );
        group.finish();
    }
}

fn encode(
    data: &[u8],
    mtu: u16,
    num_of_repair_symbols: u32,
) -> (Vec<Vec<u8>>, ObjectTransmissionInformation) {
    let encoder = Encoder::with_defaults(&data, mtu as u16);
    let config = encoder.get_config();

    (
        encoder
            .get_encoded_packets(num_of_repair_symbols)
            .iter()
            .map(|sym| sym.serialize())
            .collect(),
        config,
    )
}

criterion_group!(benches, bench_encoding, bench_decoding);
criterion_main!(benches);
