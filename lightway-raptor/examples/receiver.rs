use lightway_raptor::Raptor;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let socket = match UdpSocket::bind("127.0.0.1:6968").await {
        Ok(socket) => socket,
        Err(e) => {
            println!("UDP socket bind failed, {}", e);
            return;
        }
    };
    let decode_timeout_secs = 2;
    let mtu = 1500;
    let num_of_repair_symbols = 4;

    let mut raptor = Raptor::new(
        socket,
        None,
        decode_timeout_secs,
        Some(mtu),
        num_of_repair_symbols,
    );

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

        raptor.cleanup_decoders();
    }
}
