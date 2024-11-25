// Ferric - a simple CLI port scanning tool built in Rust.

// MIGHT HAVE TO CHANGE THE NAME
// ferric-scan, fescan, ferr1c, fe3, femap, ferr

// TODO: add tabular output functionality, 
//       fix common ports scanning (might have to refactor main function using clap for argparsing => might have to rework the cli struct)
//       add TCP SYN (half open scan) functionality

// should this / can this scan all common ports instead of user specified ones? (scan common by default, specific ones if -p flag is passed)
// how to package finished build??

use tokio::net::TcpStream; 
use tokio::time::{timeout, Duration};
use std::net::SocketAddr;
use std::path::PathBuf;
use clap::Parser; 
use clap_verbosity_flag::{Verbosity, InfoLevel};
use log::{info, error, warn, debug};
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use indoc::indoc;
use std::io::{Write, Read};
use std::fs::{self, File};
use local_ip_address::local_ip;
use dirs::config_dir;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use chrono::Local;

// List of commonly used ports
const COMMON_PORTS: &str = &"80,443,22,21,25,110,143,3306,5432,27017,6379,8080";

// Enum for the state of the ports
#[derive(Debug, Serialize, Deserialize)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Serialize, Deserialize)]
struct ScanResult {
    port: u16,
    state: PortState,
    service: String,
}

#[derive(Debug, Parser)]
#[command(
    name = "ferric",
    version = "1.0",
    author = "Aditya Rajan (ad1tya-rajan on GitHub)",
    about = "Ferric is a simple port scanning CLI tool."
)]

// get rid of the struct entirely? should we use clap somehow
struct Cli {
    #[arg(short = 's', long, value_name = "HOST", default_value_t = get_default_host())]
    host: String,

    #[arg(short = 'p', long, default_value = "1-1024", value_name = "PORTS")]
    ports: Option<String>,

    #[arg(short, long, value_name = "FORMAT", default_value = "text", value_parser = ["text", "json", "xml"])]
    output: String,

    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    xml: bool,
}

// Function to get the default IP

fn get_default_host() -> String {
    match local_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "127.0.0.1".to_string(),        
    }
}

// Function to generate filename with timestamp

fn generate_filename(extension: &str) -> String {
    let now = Local::now();
    format!("scan_results_{}.{}", now.format("%Y-%m-%d-%H-%M-%S"), extension)
}

// Function to add a welcome message on the CLI

fn print_welcome_message() {
    let mut stdout = StandardStream::stdout(ColorChoice::Always);

    let welcome_msg = indoc! {"
    =========================
    Hello, welcome to Ferric!
    =========================

    Ferric is a simple port scanner that can be used from the command line.
    It's built in Rust and uses Tokio for async I/O operations, and Clap for CLI operations.
    Use -h or --help for more information.

    Thanks :)

    v0.0.1
    Author: Aditya Rajan
    "};
    stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)).set_bold(true)).unwrap();
    writeln!(&mut stdout, "{}", welcome_msg).unwrap();
    stdout.reset().unwrap();
}

// Function to configure file path

fn configure_file_path() -> PathBuf {
    let mut config_path = config_dir().unwrap();
    config_path.push("ferric");
    config_path.push("config.toml");
    config_path
}

// Function to check if the tool is being run for the first time

fn is_first_run() -> bool {
    let config_path = configure_file_path();
    if config_path.exists() {
        let mut file = File::open(config_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents.contains("first_run = false")
    } else {
        return true
    }
}

// Function to mark the tool as run

fn mark_as_run() {
    let config_path = configure_file_path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut file = File::create(config_path).unwrap();
    writeln!(file, "first_run = false").unwrap();
}

// Function to detect services running on specific ports

async fn detect_service(port: u16) -> &'static str {
    match port {
        80 => "HTTP",
        443 => "HTTPS",
        22 => "SSH",
        21 => "FTP",
        25 => "SMTP",
        110 => "POP3",
        143 => "IMAP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        27017 => "MongoDB",
        6379 => "Redis",
        8080 => "Tomcat",
        _ => "Unknown",
    }
}

// Function to resolve domain name

async fn resolve_domain(domain: &str) -> Result<String, String> {
    let resolver = match TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()) {
        Ok(resolver) => resolver,
        Err(e) => return Err(format!("Failed to create resolver: {}", e)),
    };

    let response = match resolver.lookup_ip(domain).await {
        Ok(response) => response,
        Err(e) => return Err(format!("Failed to resolve domain: {}", e)),
    };

    let ip = match response.iter().next() {
        Some(ip) => ip,
        None => return Err("No IP address found for domain".to_string()),
    };

    Ok(ip.to_string())
}
// Function for the output of the results
// instead of outputting to terminal we want to get the results in a file with the specified format

fn output_results(results: Vec<(u16, PortState, &str)>, json: bool, xml: bool) {
    let scan_results: Vec<ScanResult> = results.into_iter()
        .map(|(port, state, service)| ScanResult { port, state, service: service.to_string() }).collect();

    if json {
        let json_str = serde_json::to_string(&scan_results).unwrap();
        let filename = generate_filename("json");
        fs::write(&filename, json_str).expect("Failed to write JSON file");
        println!("Results saved to {}", filename);
    } else if xml {
        let xml_str = quick_xml::se::to_string(&scan_results).unwrap();
        let filename = generate_filename("xml");
        fs::write(&filename, xml_str).expect("Failed to write XML file");
        println!("Results saved to {}", filename);
    }
    // } else {
    //     for result in scan_results {
    //         println!("Port: {}, State: {:?}, Service: {}", result.port, result.state, result.service);
    //     }
    // }
}

// Function to scan a port

async fn scan_port(host: &str, port: u16) -> Result<(PortState, &'static str), String> {
    let address = format!("{}:{}", host, port);
    let socket_address: SocketAddr = address.parse().map_err(|e| format!("Unable to read address: {}", e))?;

    let connect_future = TcpStream::connect(&socket_address);
    let connect_result = timeout(Duration::from_secs(1), connect_future).await; 

    match connect_result {
        Ok(Ok(_)) => Ok((PortState::Open, detect_service(port).await)),
        Ok(Err(_)) => Ok((PortState::Closed, detect_service(port).await)),
        Err(_) => Ok((PortState::Filtered, detect_service(port).await)),
    }
}

// Function to parse ports

fn parse_ports(ports: Option<&str>) -> Result<Vec<u16>, String> {

    let ports_to_parse = ports.unwrap_or(COMMON_PORTS);
    let mut ports_vec = Vec::new();

    for str_part in ports_to_parse.split(',') {
        if str_part.contains('-') {
            let mut range = str_part.split('-').map(|a| a.parse::<u16>().unwrap());
            let start = range.next().ok_or(format!("Invalid port range: {}", str_part))?;
            let end = range.next().ok_or(format!("Invalid port range: {}", str_part))?;

            if start > end {
                return Err(format!("Invalid port range: {} - {}", start, end));
            }
            ports_vec.extend(start..=end);
        } else {
            ports_vec.push(str_part.parse::<u16>().unwrap());
        }
    }
    Ok(ports_vec)
}
// Main async function

#[tokio::main]
async fn main() { // refactor using clap argparsing maybe (how much would we have to change?)
    // Initialising the logger
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    // Setting up signal handling
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // Checking for first run
    if is_first_run() {
        print_welcome_message();
        mark_as_run();
    }

    // Resolving domain
    let host = match resolve_domain(&cli.host).await {
        Ok(ip) => ip,
        Err(_) => cli.host.clone(),
    };
    
    let port_range_str = cli.ports.as_deref();

    // Parsing ports
    let port_range = match parse_ports(port_range_str) {
        Ok(range) => range,
        Err(e) => {
            error!("Error parsing ports: {}", e);
            return;
        }
    };
    debug!("DEBUG - Ports to be scanned: {:?}", port_range);
    // Scanning ports once
    let mut handles = vec![];
    let mut results = vec![];

    for port in port_range {
        let host = host.clone();
        let handle = tokio::spawn(async move {
            match scan_port(&host, port).await {
                Ok((PortState::Open, service)) => {
                    info!("Port {} is open! Service: {}", port, service);
                    Ok((port, PortState::Open, service))
                },
                Ok((PortState::Closed, service)) => {
                    info!("Port {} is closed! Service: {}", port, service);
                    Ok((port, PortState::Closed, service))
                },
                Ok((PortState::Filtered, service)) => {
                    info!("Port {} is filtered! Service: {}", port, service);
                    Ok((port, PortState::Filtered, service))
                },
                Err(e) => {
                    error!("Error scanning port {}: {}", port, e);
                    Err(e)
                },
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        match handle.await.unwrap() {
            Ok(result) => results.push(result),
            Err(e) => error!("Error scanning port: {}", e),
        }
    }

    output_results(results, cli.json, cli.xml);

    println!("Port scanning completed. Waiting for SIGINT (Ctrl+C) to exit...");

    // Wait for SIGINT signal
    tokio::signal::ctrl_c().await.expect("Failed to listen for event");

    println!("SIGINT received. Exiting...");
} 