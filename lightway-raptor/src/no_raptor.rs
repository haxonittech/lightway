use crate::LightwayDataFrame;
use crate::Transceive;
use anyhow::Result;

use std::collections::HashMap;
use tokio::net::UdpSocket;

pub struct NoRaptor {
    /// The underlying UDP socket. We can both send & receive on this socket.
    pub socket: UdpSocket,

    /// The remote to which we send frames. If you’re truly P2P,
    /// you might store multiple remotes or discover them dynamically.
    remote_addr: Option<std::net::SocketAddr>,

    /// Outgoing aggregator that stores packets to be encoded.
    outgoing_frame: LightwayDataFrame,

    /// Internal counter for sending frames (frame IDs).
    next_frame_id: u16,

    number_of_packets_per_frame: usize,

    frame_table: HashMap<u16, Vec<Vec<u8>>>,
}

impl NoRaptor {
    pub fn new(
        socket: UdpSocket,
        remote_addr: Option<std::net::SocketAddr>,
        number_of_packets_per_frame: usize,
    ) -> Self {
        Self {
            socket,
            remote_addr,
            outgoing_frame: LightwayDataFrame::new_empty(),
            next_frame_id: 0,
            number_of_packets_per_frame,
            frame_table: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl Transceive for NoRaptor {
    fn send_packet(&mut self, data: &[u8]) {
        self.outgoing_frame.add_packet(data.to_vec());
    }

    async fn flush(&mut self) -> Result<()> {
        // If empty, do nothing
        if self.outgoing_frame.is_empty() {
            return Ok(());
        }

        // Get the frame id of the current frame
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1);

        // For each packet of the frame, prepend frame_id to form one UDP packet
        for packet in self.outgoing_frame.get_all_packets() {
            let mut buf: Vec<u8> = Vec::with_capacity(packet.len() + 14);
            // 2 bytes frame_id (LE)
            buf.extend_from_slice(&frame_id.to_le_bytes());
            // symbol
            buf.extend_from_slice(&packet);

            // Send out
            if let Some(remote) = self.remote_addr {
                self.socket.send_to(&buf, remote).await?;
            } else {
                // If remote_addr is None, you might handle that differently:
                // e.g. broadcast, or store a list of remote peers, etc.
                eprintln!("No remote_addr configured for sending!");
            }
        }

        println!("Splitted out frame {frame_id}");

        // Clear aggregator
        self.outgoing_frame.clear();
        Ok(())
    }

    fn process_incoming(&mut self, data: &[u8]) -> Result<(Option<u16>, Option<Vec<Vec<u8>>>)> {
        // Minimal check
        if data.len() < 2 {
            eprintln!("Incoming packet too short: len={}", data.len());
            return Ok((None, None));
        }

        // Extract frame_id
        let frame_id = u16::from_le_bytes([data[0], data[1]]);

        let data = &data[2..];

        // Get or create a DecoderState
        let entry = self
            .frame_table
            .entry(frame_id)
            .or_insert_with(|| Vec::with_capacity(self.number_of_packets_per_frame));

        entry.push(data.into());

        if entry.len() == self.number_of_packets_per_frame {
            let result = self.frame_table.remove(&frame_id);
            return Ok((Some(frame_id), result));
        }

        // println!(
        //     "frame {frame_id} still has {} left",
        //     self.number_of_packets_per_frame - entry.len()
        // );

        // Not yet complete
        Ok((Some(frame_id), None))
    }
}
