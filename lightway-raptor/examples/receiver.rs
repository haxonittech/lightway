#[allow(unused_imports)]
use lightway_raptor::no_raptor::NoRaptor;
use lightway_raptor::{Raptor, Transceive};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    #[cfg(feature = "no_raptor")]
    println!("Please make sure that the number of packets per frame matches with the sender");

    #[cfg(feature = "no_raptor")]
    let num_of_source_packets_per_frame = 20;

    let socket = match UdpSocket::bind("127.0.0.1:6968").await {
        Ok(socket) => socket,
        Err(e) => {
            println!("UDP socket bind failed, {}", e);
            return;
        }
    };
    let decode_timeout_secs = 5; // When a decoder completes, some with the same frame id can still come. We need to make this long enough such that not too many already completed decoders get re-added to the hash map.
    let mtu = 1500;
    let num_of_repair_symbols = 4;

    #[cfg(not(feature = "no_raptor"))]
    let mut raptor = Raptor::new(
        socket,
        None,
        decode_timeout_secs,
        Some(mtu),
        num_of_repair_symbols,
    );

    // Shadown the original raptor object with NoRaptor
    #[cfg(feature = "no_raptor")]
    let mut raptor = NoRaptor::new(socket, None, num_of_source_packets_per_frame);

    println!("[Raptor] Waiting for incoming data...");

    let mut success_count = 0;
    loop {
        let mut pkt = vec![0u8; 1500]; // Max UDP packet size

        match raptor.socket.recv_from(&mut pkt).await {
            Err(e) => {
                println!(
                    "Error encountered when receiving packet from UDP socket, {}",
                    e
                );
            }
            Ok((len, _addr)) => {
                pkt.truncate(len);

                // Process the packets
                let (frame_id, decoded_packets) = match raptor.process_incoming(&pkt) {
                    Err(e) => {
                        println!("Error encountered when trying to process the packet, {}", e);
                        continue;
                    }
                    Ok(result) => result,
                };

                let frame_id = match frame_id {
                    Some(frame_id) => frame_id,
                    None => {
                        println!("Invalid packet received!");
                        continue;
                    }
                };

                match decoded_packets {
                    Some(_packets) => {
                        success_count += 1;
                        println!("Decode completed for frame {}. Current number of successful frames: {}", frame_id, success_count);
                    }
                    None => {} // println!("Frame {} is still incomplete..", frame_id),
                };
            }
        }

        // raptor.cleanup_decoders();
    }
}
