use anyhow::{Result, anyhow};
use bytesize::ByteSize;
use clap::Parser;
use lightway_app_utils::args::{Cipher, ConnectionType, Duration, LogLevel};
use lightway_core::{AuthMethod, MAX_OUTSIDE_MTU};
use std::{net::Ipv4Addr, path::PathBuf};
use twelf::config;

#[config]
#[derive(Parser, Debug)]
#[command(
    about = "Lightway client - high-performance, secure, reliable VPN protocol in Rust",
    version,
    author = "ExpressVPN <lightway-developers@expressvpn.com>",
    after_help = concat!(
        "EXAMPLES:\n",
        "    lightway-client -c client.yaml\n",
        "    lightway-client -c client.yaml --server vpn.example.com:27690\n",
        "    lightway-client -c client.yaml --mode udp --enable-pmtud\n",
        "\n",
        "See lightway-client(1) manpage for detailed configuration and usage information."
    )
)]
pub struct Config {
    /// Configuration file path (YAML format)
    /// 
    /// Supports both absolute and relative paths
    #[clap(short, long, value_name = "FILE")]
    pub config_file: PathBuf,

    /// Transport protocol to use for VPN connection
    /// TCP provides reliability, UDP provides better performance
    #[clap(short, long, value_enum, default_value_t = ConnectionType::Tcp, value_name = "PROTOCOL")]
    pub mode: ConnectionType,

    /// JWT authentication token (takes precedence over username/password)
    /// Use configuration file or environment variable instead of CLI argument
    #[clap(long, value_name = "TOKEN", hide = true)]
    pub token: Option<String>,

    /// Username for authentication
    /// Use configuration file or environment variable instead of CLI argument
    #[clap(short, long, value_name = "USER")]
    pub user: Option<String>,

    /// Password for authentication
    /// WARNING: Visible to other users when passed via CLI. Use config file or LW_CLIENT_PASSWORD env var
    #[clap(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Path to CA certificate file for server validation
    /// Ensures secure connection to authentic Lightway server
    #[clap(long, default_value = "./ca_cert.crt", value_name = "FILE")]
    pub ca_cert: PathBuf,

    /// Maximum Transmission Unit for network packets
    /// Adjust based on your network infrastructure to avoid fragmentation
    #[clap(long, default_value_t = MAX_OUTSIDE_MTU, value_name = "SIZE")]
    pub outside_mtu: usize,

    /// MTU for tunnel interface (requires CAP_NET_ADMIN capability)
    /// Override default MTU of tunnel device for performance tuning
    #[clap(long, value_name = "SIZE")]
    pub inside_mtu: Option<u16>,

    /// TUN device name (leave empty for auto-assignment)
    /// On macOS, must follow format 'utun[0-9]+' or leave empty
    #[clap(short, long, value_name = "NAME")]
    pub tun_name: Option<String>,

    /// Local IP address for tunnel interface
    /// Must be within the same subnet as peer IP
    #[clap(long, default_value = "100.64.0.6", value_name = "IP")]
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP address for tunnel interface
    /// Represents the server endpoint within the tunnel
    #[clap(long, default_value = "100.64.0.5", value_name = "IP")]
    pub tun_peer_ip: Ipv4Addr,

    /// DNS server IP address for tunnel traffic
    /// Used for resolving domain names through the VPN
    #[clap(long, default_value = "100.64.0.1", value_name = "IP")]
    pub tun_dns_ip: Ipv4Addr,

    /// Encryption cipher algorithm
    /// Both ciphers offer strong security. 
    /// However, if hardware acceleration for AES-256 is not available, 
    /// ChaCha20 may provide better performance in software implementations
    #[clap(long, value_enum, default_value_t = Cipher::Aes256, value_name = "CIPHER")]
    pub cipher: Cipher,

    /// Enable Post-Quantum Cryptography
    /// Provides protection against future quantum computing attacks
    #[cfg(feature = "postquantum")]
    #[clap(long)]
    pub enable_pqc: bool,

    /// Interval between keepalive packets (0s = disabled)
    /// Helps maintain connection through NAT devices and firewalls
    #[clap(long, default_value = "0s", value_name = "DURATION")]
    pub keepalive_interval: Duration,

    /// Timeout for keepalive responses (0s = disabled)
    /// Connection considered dead if no response within this time
    #[clap(long, default_value = "0s", value_name = "DURATION")]
    pub keepalive_timeout: Duration,

    /// Socket send buffer size for performance tuning
    /// Larger buffers may improve throughput on high-bandwidth connections
    #[clap(long, value_name = "SIZE")]
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size for performance tuning
    /// Larger buffers may improve throughput on high-bandwidth connections
    #[clap(long, value_name = "SIZE")]
    pub rcvbuf: Option<ByteSize>,

    /// Logging verbosity level
    /// Use 'debug' or 'trace' for troubleshooting connection issues
    #[clap(long, value_enum, default_value_t = LogLevel::Info, value_name = "LEVEL")]
    pub log_level: LogLevel,

    /// Enable Path MTU Discovery for UDP connections
    /// Automatically determines optimal packet size for the network path
    #[clap(long)]
    pub enable_pmtud: bool,

    /// Starting MTU size for Path MTU Discovery process
    /// Only used when --enable-pmtud is set
    #[clap(long, value_name = "SIZE")]
    pub pmtud_base_mtu: Option<u16>,

    /// Enable io_uring for high-performance tunnel I/O (Linux only)
    /// Provides better performance but requires recent Linux kernel
    #[clap(long)]
    pub enable_tun_iouring: bool,

    /// io_uring submission queue size (max 1024 for optimal performance)
    /// Only used when --enable-tun-iouring is enabled
    #[clap(long, default_value_t = 1024, value_name = "COUNT")]
    pub iouring_entry_count: usize,

    /// io_uring kernel polling idle time (0 = disabled)
    /// Uses kernel thread for polling; reduces CPU usage but may increase latency
    #[clap(long, default_value = "100ms", value_name = "DURATION")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Server domain name for certificate validation
    /// Used to verify server certificate matches expected hostname
    #[clap(long, value_name = "DOMAIN")]
    pub server_dn: Option<String>,

    /// Server address to connect to (host:port)
    /// Can be IP address or domain name with port number
    #[clap(short, long, value_name = "ADDRESS")]
    pub server: String,

    /// Enable packet encoding after connection
    /// Provides additional traffic encoding when codec is configured
    #[clap(short, long)]
    pub enable_inside_pkt_encoding_at_connect: bool,

    /// Path to save TLS keylog for Wireshark decryption (only available with `debug` feature)
    /// Enables traffic analysis and debugging of encrypted connections
    #[cfg(feature = "debug")]
    #[clap(long, value_name = "FILE")]
    pub keylog: Option<PathBuf>,

    /// Enable detailed TLS/SSL debug logging (only available with `debug` feature)
    /// Provides verbose cryptographic handshake information
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
}

impl Config {
    pub fn take_auth(&mut self) -> Result<AuthMethod> {
        match (self.token.take(), self.user.take(), self.password.take()) {
            (Some(token), _, _) => Ok(AuthMethod::Token { token }),
            (_, Some(user), Some(password)) => Ok(AuthMethod::UserPass { user, password }),
            _ => Err(anyhow!(
                "Either a token or username and password is required"
            )),
        }
    }
}
