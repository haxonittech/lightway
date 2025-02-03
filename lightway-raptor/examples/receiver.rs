#[allow(unused_imports)]
use lightway_raptor::no_raptor::NoRaptor;
#[allow(unused_imports)]
use lightway_raptor::{Raptor, Transceive};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    println!("Please make sure the total number of frames matches with the sender (so the packet loss can be computed correctly)");
    let num_of_frames = 100;

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

    #[allow(unused_variables)]
    let decode_timeout_secs = 5; // When a decoder completes, some with the same frame id can still come. We need to make this long enough such that not too many already completed decoders get re-added to the hash map.
    #[allow(unused_variables)]
    let mtu = 1500;
    #[allow(unused_variables)]
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

    // Variables and constants for tracking packet loss and throughput
    let mut start_timestamp = tokio::time::Instant::now();
    let mut first_packet_received = false;


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
                // Record the time when the first packet is received
                if !first_packet_received {
                    start_timestamp = tokio::time::Instant::now();
                    first_packet_received = true;
                }

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

                        let bytes_received_so_far = (success_count * _packets.len() * _packets[0].len()) as f64;
                        let time_difference_since_first_byte = (tokio::time::Instant::now() - start_timestamp).as_secs_f64();

                        let throughput_kbytes_per_sec = (bytes_received_so_far / 1024.0) / time_difference_since_first_byte;

                        let frame_receive_percentage = success_count as f64 / num_of_frames as f64;

                        println!("Decode completed for frame {}. Throughput in KB/s: {}, frame received percentage: {}.", frame_id, throughput_kbytes_per_sec, frame_receive_percentage);
                    }
                    None => {} // println!("Frame {} is still incomplete..", frame_id),
                };
            }
        }

        // raptor.cleanup_decoders();
    }
}
