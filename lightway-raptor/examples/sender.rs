use tokio::time::Duration;
use rand::Rng;

#[allow(unused_imports)]
use lightway_raptor::{Raptor, Transceive};

#[allow(unused_imports)]
use lightway_raptor::no_raptor::NoRaptor;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    // Parameters for Raptor
    let remote_addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 6968);
    #[allow(unused_variables)]
    let decode_timeout_secs = 2;

    #[allow(unused_variables)]
    let mtu = 1450;

    // Packets per frame
    let num_of_source_packets_per_frame = 20;

    // Size of a packet in the frame
    let source_packet_size = 1400;

    // Number of frames
    let num_of_frames = 100;

    #[allow(unused_variables)]
    let num_of_repair_symbols = num_of_source_packets_per_frame / 5;

    // Create UDP socket
    let socket = match UdpSocket::bind("127.0.0.1:6969").await {
        Ok(socket) => socket,
        Err(e) => {
            println!("UDP socket bind failed, {}", e);
            return;
        }
    };

    #[cfg(not(feature = "no_raptor"))]
    let mut raptor = Raptor::new(
        socket,
        Some(remote_addr),
        decode_timeout_secs,
        Some(mtu),
        num_of_repair_symbols,
    );

    // Shadown the original raptor object with NoRaptor
    #[cfg(feature = "no_raptor")]
    let mut raptor = NoRaptor::new(
        socket,
        Some(remote_addr),
        num_of_source_packets_per_frame as usize,
    );

    run_test(
        num_of_frames,
        num_of_source_packets_per_frame as usize,
        source_packet_size,
        &mut raptor,
    )
    .await;
}

async fn run_test<T: Transceive>(
    num_of_frames: usize,
    num_of_source_packets_per_frame: usize,
    source_packet_size: usize,
    raptor: &mut T,
) {
    let mut count: usize = 0;
    for _ in 0..num_of_frames {
        for _ in 0..num_of_source_packets_per_frame {
            let mut packet = vec![0 as u8; source_packet_size];
            for i in 0..packet.len() {
                packet[i] = rand::rng().random();
            }
            raptor.send_packet(packet.as_slice());
            count = count.wrapping_add(1);
        }

        match raptor.flush().await {
            Ok(_encoding_time) => {}
            Err(e) => println!("Flush was unsuccessful! fuck!, {}", e),
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
