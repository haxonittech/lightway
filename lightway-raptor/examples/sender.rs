use lightway_raptor::{lightway_raptor::NoRaptor, Raptor};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    // Parameters for Raptor and NoRaptor
    let remote_addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 6968);
    let decode_timeout_secs = 2;
    let mtu = 1500;
    let num_of_repair_symbols = 5;

    // Packets per frame
    let max_num_of_source_packets_per_frame = 100000;

    // Size of a packet in the frame
    let source_packet_size = 1400;

    // Number of frames
    let num_of_frames = 1;

    println!("Performance difference of different number of packets per frame");
    for num_of_source_packets_per_frame in (100..max_num_of_source_packets_per_frame).step_by(1000) {
        // Create UDP socket
        let socket = match UdpSocket::bind("127.0.0.1:6969").await {
            Ok(socket) => socket,
            Err(e) => {
                println!("UDP socket bind failed, {}", e);
                return;
            }
        };

        let mut no_raptor = NoRaptor::new(socket, Some(remote_addr));

        // println!("Source packet size: {} Bytes", source_packet_size);
        // println!(
        //     "File size: {} MBytes",
        //     (num_of_frames * num_of_source_packets_per_frame * source_packet_size) as f64
        //         / 1024.0
        //         / 1024.0
        // );
        let no_raptor_duration = run_with_no_raptor(
            num_of_frames,
            num_of_source_packets_per_frame,
            source_packet_size,
            &mut no_raptor,
        )
        .await;

        let mut raptor = Raptor::new(
            no_raptor.socket,
            Some(remote_addr),
            decode_timeout_secs,
            Some(mtu),
            num_of_repair_symbols,
        );

        let mut raptor_duration_no_repair = 0.0;
        let mut raptor_duration_five_percent_repair = 0.0;

        for num_of_repair_symbols in [0 as u32, (num_of_source_packets_per_frame / 20) as u32] {
            let raptor_duration = run_test(
                num_of_frames,
                num_of_source_packets_per_frame,
                source_packet_size,
                &mut raptor,
                num_of_repair_symbols,
            )
            .await;

            if num_of_repair_symbols == 0 {
                raptor_duration_no_repair = raptor_duration;
                // println!(
                //     "raptor takes {}% more time than no raptor",
                //     raptor_duration / no_raptor_duration * 100.0 - 100.0
                // );
            }
            else {
                raptor_duration_five_percent_repair = raptor_duration;
            }
        }

        println!(
            "{num_of_source_packets_per_frame}\t{raptor_duration_five_percent_repair}\t{no_raptor_duration}\t{}", raptor_duration_five_percent_repair/no_raptor_duration*100.0-100.0
        );
    }
}

async fn run_test(
    num_of_frames: usize,
    num_of_source_packets_per_frame: usize,
    source_packet_size: usize,
    raptor: &mut Raptor,
    num_of_repair_symbols: u32,
) -> f64 {
    let start_time = tokio::time::Instant::now();

    let mut total_encoding_time = 0.0;

    let mut count: usize = 0;
    for _ in 0..num_of_frames {
        for _ in 0..num_of_source_packets_per_frame {
            let packet = vec![count as u8; source_packet_size];
            raptor.send_packet(packet.as_slice());
            count = count.wrapping_add(1);
        }

        match raptor.flush().await {
            Ok(encoding_time) => {
                total_encoding_time += encoding_time.as_secs_f64();
            }
            Err(e) => println!("Flush was unsuccessful! fuck!, {}", e),
        }
    }
    let end_time = tokio::time::Instant::now();

    let time_took = (end_time - start_time).as_secs_f64();

    // println!("Took {time_took} secs with num of repair symbols: {num_of_repair_symbols}. Encoding time: {total_encoding_time} seconds, encoding time took {}% of the time", total_encoding_time/time_took as f64 * 100.0);

    time_took
}

async fn run_with_no_raptor(
    num_of_frames: usize,
    num_of_source_packets_per_frame: usize,
    source_packet_size: usize,
    no_raptor: &mut NoRaptor,
) -> f64 {
    let start_time = tokio::time::Instant::now();

    let mut count: usize = 0;
    for _ in 0..num_of_frames {
        for _ in 0..num_of_source_packets_per_frame {
            let packet = vec![count as u8; source_packet_size];
            no_raptor.send_packet(packet.as_slice());
            count = count.wrapping_add(1);
        }

        match no_raptor.flush().await {
            Ok(()) => {}
            Err(e) => println!("Flush was unsuccessful! fuck!, {}", e),
        }
    }
    let end_time = tokio::time::Instant::now();

    let time_took = (end_time - start_time).as_secs_f64();
    // println!("It took {time_took} seconds with no raptor");

    time_took
}
