use std::env;
use std::fs;
use std::path::Path;

use clap::CommandFactory;

#[path = "src/args.rs"]
mod args;

fn create_server_command() -> clap::Command {
    // Get the base command from the derive macro
    let cmd = args::Config::command();

    // Add the detailed help text
    let long_about = [
        "Lightway is a modern VPN server that implements the Lightway protocol. It provides",
        "a high-performance, secure VPN service using modern cryptographic algorithms and",
        "optimized network protocols.",
        "",
        "The server accepts connections from Lightway clients and provides secure tunneling",
        "services. It supports multiple authentication methods, dynamic IP assignment, and",
        "advanced features like PROXY protocol support and io_uring optimization on Linux.",
        "",
        "Configuration can be provided via YAML files, environment variables (LW_SERVER_*),",
        "or command-line arguments. Command-line arguments have the highest priority.",
        "",
        "Authentication: Supports both username/password (htpasswd format) and JWT token",
        "authentication. Only bcrypt, SHA-256, and SHA-512 password hashes are supported.",
    ]
    .join("\n");

    let after_help = [
        "CONFIGURATION FILE:",
        "The server requires a configuration file in YAML format. Environment variables can",
        "override configuration file settings using the LW_SERVER_ prefix. Command-line",
        "arguments have the highest priority.",
        "",
        "Example configuration:",
        "    mode: tcp",
        "    bind_address: \"0.0.0.0:27690\"",
        "    server_cert: \"/etc/lightway/server.crt\"",
        "    server_key: \"/etc/lightway/server.key\"",
        "    user_db: \"/etc/lightway/users.db\"",
        "    ip_pool: \"10.125.0.0/16\"",
        "    log_level: info",
        "    key_update_interval: \"15m\"",
        "",
        "AUTHENTICATION:",
        "The server supports multiple authentication methods:",
        "  • Username/Password: Uses Apache htpasswd compatible format. Only bcrypt,",
        "    SHA-256, and SHA-512 hashes are supported (not Apache MD5).",
        "  • JWT Token: Uses RSA public key to validate JWT tokens with RS256 algorithm.",
        "    Tokens must include a valid \"exp\" claim.",
        "",
        "Both methods can be enabled simultaneously. Each client connection uses one",
        "method chosen by the client.",
        "",
        "SECURITY CONSIDERATIONS:",
        "  • Ensure proper file permissions on certificate files (600 recommended)",
        "  • Use strong passwords and modern hashing algorithms for user database",
        "  • Regularly rotate JWT signing keys",
        "  • Monitor key update intervals for optimal security",
        "  • Use appropriate IP pool ranges to avoid conflicts",
        "",
        "EXAMPLES:",
        "    lightway-server --config-file /etc/lightway/server.yaml",
        "    lightway-server -c server.yaml --ip-pool 192.168.100.0/24 --log-level debug",
        "    lightway-server -c server.yaml --mode udp",
        "    lightway-server -c server.yaml --proxy-protocol",
        "",
        "ENVIRONMENT:",
        "    LW_SERVER_BIND_ADDRESS     Server bind address",
        "    LW_SERVER_LOG_LEVEL        Logging level",
        "    LW_SERVER_USER_DB          Path to user database file",
        "    LW_SERVER_IP_POOL          Client IP pool subnet",
        "",
        "SEE ALSO:",
        "    lightway-client(1), htpasswd(1), ip(8), iptables(8)",
        "",
        "REPORT BUGS:",
        "    https://github.com/expressvpn/lightway/issues",
    ]
    .join("\n");

    cmd.long_about(long_about)
        .after_help(after_help)
}

fn main() -> std::io::Result<()> {
    // Generate man page using clap_mangen
    let cmd = create_server_command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;

    // We can't use CARGO_TARGET_DIR in build.rs, ugly hack to get the target directory
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_path = Path::new(&out_dir).ancestors().nth(3).unwrap();

    // Create man directory if it doesn't exist
    let man_path = target_path.join("man");
    fs::create_dir_all(&man_path).unwrap();

    // Write to file
    let name = env::var("CARGO_PKG_NAME").unwrap();
    let manpage = man_path.join(format!("{}.1", name));
    fs::write(manpage, buffer)?;

    Ok(())
}
