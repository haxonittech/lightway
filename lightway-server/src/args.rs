use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
};

use bytesize::ByteSize;
use clap::Parser;
use ipnet::Ipv4Net;
use twelf::config;

use lightway_app_utils::args::{ConnectionType, Duration, IpMap, LogFormat, LogLevel};

#[config]
#[derive(Parser, Debug)]
#[command(
    about = "Lightway server - high-performance, secure, reliable VPN protocol in Rust",
    version,
    author = "ExpressVPN <lightway-developers@expressvpn.com>",
    after_help = concat!(
        "EXAMPLES:\n",
        "    lightway-server -c server.yaml\n",
        "    lightway-server -c server.yaml --ip-pool 192.168.100.0/24\n",
        "    lightway-server -c server.yaml --mode udp --proxy-protocol\n",
        "\n",
        "See lightway-server(1) manpage for detailed configuration and usage information."
    )
)]
pub struct Config {
    /// Configuration file path (YAML format)
    /// Supports both absolute and relative paths
    #[clap(short, long, value_name = "FILE")]
    pub config_file: PathBuf,

    /// Transport protocol for client connections
    /// TCP provides reliability, UDP provides better performance
    #[clap(short, long, value_enum, default_value_t=ConnectionType::Tcp, value_name = "PROTOCOL")]
    pub mode: ConnectionType,

    /// Path to user database file (Apache htpasswd format)
    /// Supports bcrypt, SHA-256, and SHA-512 password hashes only
    #[clap(long, value_name = "FILE")]
    pub user_db: Option<PathBuf>,

    /// RSA public key file for JWT token validation (PEM format)
    /// Used to verify RS256-signed JWT tokens from clients
    #[clap(long, value_name = "FILE")]
    pub token_rsa_pub_key_pem: Option<PathBuf>,

    /// Path to server TLS certificate file
    /// Must be valid X.509 certificate in PEM format
    #[clap(long, default_value = "./server.crt", value_name = "FILE")]
    pub server_cert: PathBuf,

    /// Path to server TLS private key file
    /// Must correspond to the server certificate
    #[clap(long, default_value = "./server.key", value_name = "FILE")]
    pub server_key: PathBuf,

    /// TUN device name for tunnel interface
    /// Must be unique if running multiple server instances
    #[clap(long, default_value = "lightway", value_name = "NAME")]
    pub tun_name: String,

    /// IP address pool for client assignment (CIDR notation)
    /// All connected clients receive IPs from this range
    #[clap(long, default_value = "10.125.0.0/16", value_name = "SUBNET")]
    pub ip_pool: Ipv4Net,

    /// Custom IP mapping for specific client source addresses
    /// Maps incoming IP to a specific subnet within the main IP pool
    #[clap(long, value_name = "MAP")]
    pub ip_map: Option<IpMap>,

    /// IP address for the server's TUN device
    /// Reserved from the IP pool if within that range
    #[clap(long, value_name = "IP")]
    pub tun_ip: Option<Ipv4Addr>,

    /// Server IP address sent to clients in network configuration
    /// Represents the server endpoint within the tunnel
    #[clap(long, default_value = "10.125.0.6", value_name = "IP")]
    pub lightway_server_ip: Ipv4Addr,

    /// Default client IP address for network configuration
    /// Template for client tunnel interface configuration
    #[clap(long, default_value = "10.125.0.5", value_name = "IP")]
    pub lightway_client_ip: Ipv4Addr,

    /// DNS server IP address sent to clients
    /// Used by clients for domain name resolution through VPN
    #[clap(long, default_value = "10.125.0.1", value_name = "IP")]
    pub lightway_dns_ip: Ipv4Addr,

    /// Enable Post-Quantum Cryptography
    /// Provides protection against future quantum computing attacks
    #[clap(long)]
    pub enable_pqc: bool,

    /// Enable io_uring for high-performance tunnel I/O (Linux only)
    /// Provides better performance but requires recent Linux kernel
    #[clap(long)]
    pub enable_tun_iouring: bool,

    /// io_uring submission queue size (max 1024 for optimal performance)
    /// Only used when --enable-tun-iouring is enabled
    #[clap(long, default_value_t = 1024, value_name = "COUNT")]
    pub iouring_entry_count: usize,

    /// Submission-queue polling idle time (milliseconds):
    /// how long the kernel SQPOLL thread will wait for new submissions
    /// before sleeping. 0 disables SQPOLL entirely. Higher values
    /// reduce CPU usage (longer sleeps) but add latency on wakeup.
    #[clap(long, default_value = "100ms", value_name = "DURATION")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Log output format for different use cases
    /// 'json' is recommended for structured logging and monitoring
    #[clap(long, value_enum, default_value_t = LogFormat::Full, value_name = "FORMAT")]
    pub log_format: LogFormat,

    /// Logging verbosity level
    /// Use 'debug' or 'trace' for troubleshooting server issues
    #[clap(long, value_enum, default_value_t = LogLevel::Info, value_name = "LEVEL")]
    pub log_level: LogLevel,

    /// Interval for automatic TLS/DTLS key rotation
    /// More frequent updates improve security but may impact performance
    #[clap(long, default_value = "15m", value_name = "DURATION")]
    pub key_update_interval: Duration,

    /// Server bind address and port (host:port)
    /// Use 0.0.0.0 to listen on all interfaces
    #[clap(long, default_value = "0.0.0.0:27690", value_name = "ADDRESS")]
    pub bind_address: SocketAddr,

    /// Number of bind retry attempts if address is in use
    /// Waits 1 second between attempts; useful for service restarts
    #[clap(long, default_value_t = NonZeroUsize::MIN, value_name = "COUNT")]
    pub bind_attempts: NonZeroUsize,

    /// Enable PROXY protocol v1/v2 support (TCP mode only)
    /// Required when running behind load balancers like HAProxy
    #[clap(long)]
    pub proxy_protocol: bool,

    /// UDP socket buffer size for performance tuning
    /// Larger buffers improve performance on high-throughput connections
    #[clap(long, default_value_t = ByteSize::mib(15), value_name = "SIZE")]
    pub udp_buffer_size: ByteSize,

    /// Enable detailed TLS/SSL debug logging (only available with `debug` feature)
    /// Provides verbose cryptographic handshake information
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
}
