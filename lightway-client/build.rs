use std::env;
use std::fs;
use std::path::Path;

use clap::CommandFactory;

#[path = "src/args.rs"]
mod args;

fn create_client_command() -> clap::Command {
    // Get the base command from the derive macro
    let cmd = args::Config::command();

    // Add the detailed help text
    let long_about = [
        "Lightway is a modern VPN client that implements the Lightway protocol. It provides",
        "a fast, secure, and reliable VPN connection using modern cryptographic algorithms",
        "and optimized network protocols.",
        "",
        "The client connects to a Lightway server and establishes a secure tunnel for",
        "routing network traffic. It supports both TCP and UDP transport protocols and",
        "includes advanced features like Path MTU Discovery, keepalive mechanisms, and",
        "io_uring optimization on Linux.",
        "",
        "Configuration can be provided via YAML files, environment variables (LW_CLIENT_*),",
        "or command-line arguments. Command-line arguments have the highest priority.",
        "",
        "Security Note: Avoid passing passwords via command-line arguments as they may be",
        "visible to other users. Use configuration files or environment variables instead.",
    ]
    .join("\n");

    let after_help = [
        "CONFIGURATION FILE:",
        "The client requires a configuration file in YAML format. Environment variables can",
        "override configuration file settings using the LW_CLIENT_ prefix. Command-line",
        "arguments have the highest priority.",
        "",
        "Example configuration:",
        "    mode: tcp",
        "    server: \"vpn.example.com:27690\"",
        "    user: \"myuser\"",
        "    password: \"mypassword\"",
        "    ca_cert: \"/etc/lightway/ca.crt\"",
        "    log_level: info",
        "",
        "AUTHENTICATION:",
        "The client supports two authentication methods:",
        "  • Username/Password: Traditional username and password authentication",
        "  • JWT Token: JSON Web Token authentication using RS256 algorithm",
        "",
        "If both token and username/password are provided, token authentication takes precedence.",
        "",
        "EXAMPLES:",
        "    lightway-client --config-file /etc/lightway/client.yaml",
        "    lightway-client -c client.yaml --server vpn.example.com:27690 --log-level debug",
        "    lightway-client -c client.yaml --mode udp --enable-pmtud",
        "",
        "FILES:",
        "    /etc/lightway/client.yaml    System-wide client configuration",
        "    ~/.config/lightway/client.yaml    User-specific client configuration",
        "    ./ca_cert.crt    Default CA certificate location",
        "",
        "ENVIRONMENT:",
        "    LW_CLIENT_SERVER       Server address",
        "    LW_CLIENT_USER         Username for authentication",
        "    LW_CLIENT_PASSWORD     Password for authentication",
        "    LW_CLIENT_LOG_LEVEL    Logging level",
        "",
        "SEE ALSO:",
        "    lightway-server(1), ip(8), iptables(8)",
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
    let cmd = create_client_command();
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
