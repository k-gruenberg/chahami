#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use eframe::egui::Color32;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::{RwLock, Arc};
use std::net::{IpAddr, SocketAddr};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use std::str::FromStr;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

const MAX_NUMBER_OF_PEERS: usize = 10; // ToDo: dynamically increase when all 10 fields are full (or when sth. is intered into the last field)
const CHAHAMI_PORT: u16 = 13130; // UDP ports CHAHAMI_PORT to CHAHAMI_PORT+MAX_NUMBER_OF_PEERS-1 will be used for communication
const PUNCH_INTERVAL_IN_MILLIS: f64 = 5_000.0; // the punch time is every 5,000 milliseconds
const PUNCH_TIMEOUT: u64 = 4_000; // after having punched, wait 4,000 milliseconds for a response until considering the punch as a failure
const PUNCH_MESSAGE_PREFIX: &str = "PUNCH"; // the prefix of the message sent when punching
//const ACK_PUNCH_MESSAGE_PREFIX: &str = "ACKPUNCH"; // the prefix of the 2nd message sent when punching // ToDo: would make incorrectly assuming a punch to have been successful much less likely
const QUIC_SERVER_SETUP_TIME_IN_MILLIS: u64 = 3_000; // the time that the QUIC client will wait until trying to connect to the QUIC server
const QUIC_CLIENT_CONNECT_TIMEOUT: u64 = 10_000; // the time that the QUIC client will wait for the connection to succeed before timing out and re-punshing
const QUIC_SERVER_ACCEPT_TIMEOUT: u64 = 10_000; // the time that the QUIC server will wait for an connection before timing out; has to be larger than QUIC_SERVER_SETUP_TIME_IN_MILLIS!
const ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS: u64 = 3_000; // the amount of time to display an error message to the user

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(320.0, 370.0)),
        ..Default::default()
    };
    eframe::run_native(
        &format!("Chahami v{}", env!("CARGO_PKG_VERSION")),
        options,
        Box::new(|_cc| Box::new(ChahamiApp::default())),
    );
}

struct ChahamiApp {
    tokio_runtime: Arc<tokio::runtime::Runtime>,
    my_global_ip_address: String,
    persistent_data: ChahamiAppPersistentData,
    status_labels: Arc<[RwLock<String>; MAX_NUMBER_OF_PEERS]>,
    gone: bool, // = whether the "Go!" button has been clicked
}

/// Stores the user settings that shall persistent when the user closes and then reopens the app.
#[derive(Serialize, Deserialize, Debug)]
struct ChahamiAppPersistentData {
    port_shared: String,
    peer_ip_addresses: [String; MAX_NUMBER_OF_PEERS],
}

impl Default for ChahamiApp {
    fn default() -> Self {
        Self {
            tokio_runtime: Arc::new(tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()),
            my_global_ip_address: get_my_global_ip_address().unwrap_or("?????".to_owned()), // ToDo: use future instead!!!!!
            persistent_data: ChahamiAppPersistentData::load().unwrap_or_else(|_| ChahamiAppPersistentData::default()),
            status_labels: Default::default(),
            gone: false,
        }
    }
}

impl Default for ChahamiAppPersistentData {
    fn default() -> Self {
        Self {
            port_shared: "".to_owned(),
            peer_ip_addresses: Default::default(),
        }
    }
}

impl ChahamiAppPersistentData {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let home_dir: PathBuf = dirs::home_dir().ok_or("could not get home directory")?;

        let mut chahami_dir: PathBuf = home_dir;
        chahami_dir.push(".chahami");

        let mut chahami_config_json: PathBuf = chahami_dir;
        chahami_config_json.push("config.json");
    
        if chahami_config_json.exists() {
            Ok(serde_json::from_str(std::str::from_utf8(&std::fs::read(chahami_config_json)?)?)?)
        } else {
            Ok(Self::default())
        }
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let home_dir: PathBuf = dirs::home_dir().ok_or("could not get home directory")?;

        let mut chahami_dir: PathBuf = home_dir;
        chahami_dir.push(".chahami");
        if !chahami_dir.exists() {
            std::fs::create_dir(&chahami_dir)?;
        }

        let mut chahami_config_json: PathBuf = chahami_dir;
        chahami_config_json.push("config.json");

        std::fs::write(&chahami_config_json, serde_json::to_string(&self)?)?;

        Ok(())
    }
}

impl eframe::App for ChahamiApp {
    fn on_close_event(&mut self) -> bool { // ToDo: ask when user tries to close window AND self.gone==true, cf. https://github.com/emilk/egui/blob/master/examples/confirm_exit/src/main.rs
        if let Err(err) = self.persistent_data.save() {
            eprintln!("Persisting data failed: {}", err);
        }
        true // do not abort closing
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Chahami");

            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let seconds = now % 60;
            let minutes = (now / 60) % 60;
            let hours = (now / 3600) % 24;
            ui.label(format!("Your system time (UTC): {:02}:{:02}:{:02}", hours, minutes, seconds));

            ui.label(format!("Your global IP address: {}", &mut self.my_global_ip_address));
            
            let port_shared_is_valid: bool = self.persistent_data.port_shared.parse::<u16>().is_ok();
            ui.horizontal(|ui| {
                let my_port_label = ui.label("The port you share: ");
                ui.style_mut().spacing.text_edit_width = 50.0;
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.persistent_data.port_shared)
                    .interactive(!self.gone) // disables editing once "Go!" has been pressed
                    .text_color(if port_shared_is_valid {Color32::LIGHT_GREEN} else {Color32::RED})
                );
                response.labelled_by(my_port_label.id);
            });

            ui.label(format!("Your peers:"));
            for i in 0..MAX_NUMBER_OF_PEERS {
                ui.horizontal(|ui| {
                    ui.label(format!("#{}", i));
                    ui.style_mut().spacing.text_edit_width = 125.0;
                    let ip_addr_is_valid = IpAddr::from_str(&self.persistent_data.peer_ip_addresses[i]).is_ok();
                    ui.add(
                        egui::TextEdit::singleline(&mut self.persistent_data.peer_ip_addresses[i])
                        .interactive(!self.gone) // disables editing once "Go!" has been pressed
                        .text_color(if ip_addr_is_valid {Color32::LIGHT_GREEN} else {Color32::RED})
                    );
                    ui.label(format!("{}", self.status_labels[i].read().unwrap()));
                });
            }

            if !self.gone {
                if ui.button("Go!").clicked() {
                    // Clicking "Go!" only works when the shared port text field
                    // is either empty or contains a valid port number:
                    if self.persistent_data.port_shared.trim() == "" || port_shared_is_valid {
                        self.gone = true;
                        go(
                            self.tokio_runtime.clone(),
                            self.persistent_data.port_shared.clone(),
                            self.persistent_data.peer_ip_addresses.clone(),
                            self.status_labels.clone()
                        );
                    }
                }
            }

            ui.label("Do NOT close this window!");
            // Not showing the following help info because it makes the UI look ugly:
            //ui.label("Server peer and client peer must enter their");
            //ui.label("respective IP addresses under the same # index.");
        });

        // https://www.reddit.com/r/rust/comments/we84ch/how_do_i_comunicate_with_an_egui_app/:
        // "You can force eframe to call update again as soon as possible by
        //  calling request_repaint() on the egui Context, if you call this
        //  every time in update then it will run in a loop constantly
        //  regardless of if the gui needs to be repainted or not." (user Googe14)
        //
        // This is necessary here because within the tasks spawned by the go()
        // function, the status_labels will be updated.
        // Passing the context to these tasks is not easily possible due to
        // lifetimes.
        ctx.request_repaint();
    }
}

fn get_my_global_ip_address() -> Option<String> {
    // https://docs.rs/reqwest/latest/reqwest/blocking/struct.ClientBuilder.html
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build().ok()?;
    // https://docs.rs/reqwest/latest/reqwest/blocking/struct.Client.html
    let mut resp = client.get("https://httpbin.org/ip").send().ok()?
    // https://crates.io/crates/reqwest
        .json::<HashMap<String, String>>().ok()?;
    return resp.remove("origin");
}

/// Executed when the user clicks the "Go!" button:
fn go(tokio_runtime: Arc<tokio::runtime::Runtime>,
    port_shared: String, peer_ip_addresses: [String; MAX_NUMBER_OF_PEERS],
    status_labels: Arc<[RwLock<String>; MAX_NUMBER_OF_PEERS]>) {
    // Both QUIC client and QUIC server need the server's certificate (and key in case of the server):
    // Beware that this is only because of a requirement of the s2n_quic crate used,
    // it does not add much of security since the private key is hardcoded and publicly known!
    
    let home_dir: PathBuf = dirs::home_dir().expect("could not get home directory");

    let mut chahami_dir: PathBuf = home_dir;
    chahami_dir.push(".chahami");
    if !chahami_dir.exists() {
        std::fs::create_dir(&chahami_dir).expect("could not create '.chahami' dir in home dir");
    }

    let mut quic_server_cert_file_path: PathBuf = chahami_dir.clone();
    quic_server_cert_file_path.push("quic_server_cert.pem");
    
    let mut quic_server_key_file_path: PathBuf = chahami_dir.clone();
    quic_server_key_file_path.push("quic_server_key.pem");
    
    if !quic_server_cert_file_path.exists() {
        std::fs::write(&quic_server_cert_file_path, include_str!("../quic_server_cert.pem")).expect("writing to cert file failed");
    }
    
    if !quic_server_key_file_path.exists() {
        std::fs::write(&quic_server_key_file_path, include_str!("../quic_server_key.pem")).expect("writing to key file failed");
    }

    for i in 0..MAX_NUMBER_OF_PEERS {
        if peer_ip_addresses[i].trim() != "" { // For each peer the user specified:
            let port_shared = port_shared.clone();
            let peer_ip_address = peer_ip_addresses[i].clone();
            let status_labels = status_labels.clone();
            let quic_server_cert_file_path_clone = quic_server_cert_file_path.clone();
            let quic_server_key_file_path_clone = quic_server_key_file_path.clone();
            let tokio_runtime_clone_1 = tokio_runtime.clone();
            let tokio_runtime_clone_2 = tokio_runtime.clone();
            let tokio_runtime_clone_3 = tokio_runtime.clone();
            tokio_runtime_clone_1.spawn(async move { // Note: punching will be performed concurrently, which has both its upsides and its downsides...
                let mut first_loop_iteration = true;
                loop { // Looping to restart punching when the QUIC connection fails (initially or sometime later):
                    
                    if !first_loop_iteration { // In the first loop iteration there's no previous error to display or used port to wait for being freed:
                        // Before punching again, wait a few seconds to allow the user to see and read the error message printed at the end of the loop:
                        tokio::time::sleep(Duration::from_millis(ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS)).await;
                        // Note: The sleep should also allow the operating system to free up the ports again because punching on them again.
                    }
                    first_loop_iteration = false;

                    // Prepare UDP socket (will be used for punching and then for the QUIC connection):
                    let remote_addr = IpAddr::from_str(&peer_ip_address).unwrap();
                    let remote_port = CHAHAMI_PORT + (i as u16);
                    let local_addr = if remote_addr.is_ipv4() {"0.0.0.0"} else {"::"}; // choose ipv6 wildcard address when remote_addr is an ipv6 address !!!!!
                    let local_port = CHAHAMI_PORT + (i as u16);
                    let udp_socket;
                    loop {
                        match UdpSocket::bind((local_addr, local_port)).await {
                            Ok(socket) => {
                                udp_socket = socket;
                                break;
                            },
                            Err(err) => {
                                *status_labels[i].write().unwrap() = format!("Error binding UDP socket: {}", err);
                                tokio::time::sleep(Duration::from_millis(ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS)).await;
                            }
                        }
                    }
                    while let Err(err) = udp_socket.connect((remote_addr, remote_port)).await {
                        *status_labels[i].write().unwrap() = format!("Error connecting UDP socket: {}", err);
                        tokio::time::sleep(Duration::from_millis(ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS)).await;
                    }

                    // Punching:
                    let mut counter = 0;
                    *status_labels[i].write().unwrap() = format!("Punching...");
                    // Try punching (and punching (and punching ...)):
                    loop {
                        match punch_hole(&udp_socket).await {
                            Ok(false) => { // UDP hole punching failed:
                                counter += 1;
                                *status_labels[i].write().unwrap() = format!("Punching failed {} times", counter);
                                // continue (innermost) loop and try again... (and again and again and again...)
                            },
                            Ok(true) => { // UDP hole punching succeeded:
                                *status_labels[i].write().unwrap() = format!("Punching succeeded");
                                break; // break out of (innermost) loop to stop punching
                            },
                            Err(err) => { // UDP hole punching could not be performed at all due to a tokio::io::Error (e.g. an "address already in use" error):
                                *status_labels[i].write().unwrap() = format!("Couldn't punch: {}", err);

                                // Wait a few seconds to allow the user to see and read the error message printed above:
                                // Also: when puch_hole() failed with an error (e.g. "address already in use"),
                                //       there's really no point point in *immediately* trying to call it again!
                                tokio::time::sleep(Duration::from_millis(ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS)).await;

                                // continue (innermost) loop and try again... (and again and again and again...)
                            }
                        }
                    }

                    // After punching succeeded, (A) connect using QUIC and (B) start localhost forwarding:

                    if port_shared.trim() == "" { // We are a client peer: Build a QUIC client:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        // Wait a little before starting the QUIC client such that the other peer may start its QUIC server:
                        *status_labels[i].write().unwrap() = format!("Waiting before connecting to QUIC server...");
                        tokio::time::sleep(Duration::from_millis(QUIC_SERVER_SETUP_TIME_IN_MILLIS)).await;

                        // (A) QUIC client (cf. https://github.com/quinn-rs/quinn/blob/main/quinn/examples/client.rs):
                        let mut roots = rustls::RootCertStore::empty();
                        match pem_file_to_rustls_certificates(&quic_server_cert_file_path_clone.clone()) {
                            Ok(certs) if certs.len() >= 1 => {
                                roots.add(&certs.last().unwrap()).unwrap();
                                // cf. https://serverfault.com/questions/476576/how-to-combine-various-certificates-into-single-pem
                                // or more specifically https://www.rfc-editor.org/rfc/rfc4346#section-7.4.2:
                                //   "The sender's certificate must come first in the list.
                                //    Each following certificate must directly certify the one preceding it."
                            }
                            Ok(_certs) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: QUIC server cert file contains no certs");
                                return;
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                                *status_labels[i].write().unwrap() = format!("Fatal: QUIC server certificate file not found");
                                return;
                            }
                            Err(e) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: Failed to open QUIC server certificate file: {}", e);
                                return;
                            }
                        }
                        let client_crypto = rustls::ClientConfig::builder()
                            .with_safe_defaults()
                            .with_root_certificates(roots)
                            .with_no_client_auth();

                        let blocking_std_udp_socket = udp_socket.into_std().unwrap();
                        blocking_std_udp_socket.set_nonblocking(false).unwrap();
                        match quinn::Endpoint::new(Default::default(), None, blocking_std_udp_socket, quinn::TokioRuntime {}) {
                            Ok(mut quic_client_endpoint) => {
                                quic_client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

                                *status_labels[i].write().unwrap() = format!("Connecting to QUIC server...");
                                match tokio::time::timeout(Duration::from_millis(QUIC_CLIENT_CONNECT_TIMEOUT), quic_client_endpoint.connect((remote_addr, remote_port).into(), "chahami").unwrap()).await { // "chahami" = hostname
                                    Ok(Ok(conn)) => {
                                        *status_labels[i].write().unwrap() = format!("Connected to QUIC server");
                                        match conn.open_bi().await {
                                            Ok((mut quic_send_stream, mut quic_receive_stream)) => {
                                                // (B) localhost TCP server (to which the client application will connect):
                                                let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap(); // Port number = 0 means OS will assign a port
                                                let listener = TcpListener::bind(&addr).await.unwrap();

                                                // Display the user the address of the local TCP proxy to connect to:
                                                let listener_local_addr;
                                                match listener.local_addr() { //.unwrap_or("failed to get local TCP proxy addr");
                                                    Ok(local_addr) => {
                                                        listener_local_addr = local_addr;
                                                        *status_labels[i].write().unwrap() = format!("{}", listener_local_addr);
                                                    },
                                                    Err(err) => {
                                                        *status_labels[i].write().unwrap() = format!("Fatal: Failed to get local TCP proxy addr: {}", err);
                                                        return; // return from the whole async block to stop handling this peer entirely; do *NOT* continue to try punching
                                                    }
                                                }

                                                // Now wait for the user to connect:
                                                match listener.accept().await {
                                                    Ok((tcp_stream, _remote_peer)) => {
                                                        *status_labels[i].write().unwrap() = format!("Accepted local conn on {}", listener_local_addr);

                                                        // One needs to use .into_split() as suggested on https://github.com/tokio-rs/tokio-core/issues/198:
                                                        let (mut tcp_read_stream, mut tcp_write_stream) = tcp_stream.into_split();

                                                        // Link (A) and (B) together using two new tasks
                                                        //   and join the two in order to continue the loop and start re-punching when either the
                                                        //   global QUIC connection or the local TCP connection fails/is terminated:
                                                        let receive_task = tokio_runtime_clone_2.spawn(async move {
                                                            // Write everything to our TCP client that we receive via QUIC:
                                                            println!("writing test: client software writes to local TCP client");
                                                            tokio::io::copy(&mut "test: client software writes to local TCP client".as_ref(), &mut tcp_write_stream).await.unwrap();
                                                            tokio::io::copy(&mut quic_receive_stream, &mut tcp_write_stream).await.unwrap();
                                                        });
                                                        let send_task = tokio_runtime_clone_3.spawn(async move {
                                                            // Write everything to our QUIC server that we receive from our TCP client:
                                                            println!("writing test: client software writes to QUIC stream");
                                                            tokio::io::copy(&mut "test: client software writes to QUIC stream".as_ref(), &mut quic_send_stream).await.unwrap();
                                                            tokio::io::copy(&mut tcp_read_stream, &mut quic_send_stream).await.unwrap();
                                                        });

                                                        let _ = tokio::join!(send_task, receive_task); // When both fail/terminate, ...
                                                        *status_labels[i].write().unwrap() = format!("Local TCP conn or QUIC conn lost");
                                                        // ...the punching process will be started again...
                                                    }
                                                    Err(err) => {
                                                        *status_labels[i].write().unwrap() = format!("Accepting local conn failed: {}", err);
                                                    }
                                                }

                                                // Clean up the QUIC connection before beginning to punch again:
                                                conn.close(0u32.into(), b"close");
                                                quic_client_endpoint.wait_idle().await; // Give the server a fair chance to receive the close packet
                                            },
                                            Err(err) => {
                                                *status_labels[i].write().unwrap() = format!("Failed to open bi stream to QUIC server: {}", err);
                                            }
                                        }
                                    },
                                    Err(timeout_err) => {
                                        *status_labels[i].write().unwrap() = format!("Failed to connect to QUIC server due to timeout: {}", timeout_err);
                                    },
                                    Ok(Err(connect_err)) => {
                                        *status_labels[i].write().unwrap() = format!("Failed to connect to QUIC server: {}", connect_err);
                                    }
                                }
                            },
                            Err(err) => {
                                *status_labels[i].write().unwrap() = format!("Creating QUIC client endpoint failed: {}", err);
                            }
                        }
                    } else { // We are a server peer: Build a QUIC server:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        let localhost_port_shared: u16 = port_shared.parse().expect("invalid port number");

                        // (A) QUIC server (cf. https://github.com/quinn-rs/quinn/blob/main/quinn/examples/server.rs):
                        let (cert_chain, key) = match (pem_file_to_rustls_certificates(&quic_server_cert_file_path_clone.clone()), pem_file_to_rustls_private_key(&quic_server_key_file_path_clone.clone())) {
                            (Ok(x), Ok(y)) => (x, y),
                            (Err(e1), Ok(_)) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: Failed to read QUIC server cert file: {}", e1);
                                return;
                            },
                            (Ok(_), Err(e2)) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: Failed to read QUIC server key file: {}", e2);
                                return;
                            },
                            (Err(e1), Err(e2)) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: Failed to read QUIC server cert and key files: {}; {}", e1, e2);
                                return;
                            },
                        };

                        let server_crypto;
                        match rustls::ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(cert_chain, key) {
                            Ok(crypto) => {
                                server_crypto = crypto;
                            },
                            Err(err) => {
                                *status_labels[i].write().unwrap() = format!("Fatal: Creating QUIC server config failed: {}", err);
                                return;
                            }
                        }

                        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
                        Arc::get_mut(&mut server_config.transport)
                            .unwrap()
                            .max_concurrent_uni_streams(0_u8.into());

                        let blocking_std_udp_socket = udp_socket.into_std().unwrap();
                        blocking_std_udp_socket.set_nonblocking(false).unwrap();
                        match quinn::Endpoint::new(Default::default(), Some(server_config), blocking_std_udp_socket, quinn::TokioRuntime {}) {
                            Ok(quic_server_endpoint) => {
                                // Wait for other peer (QUIC client) to connect:
                                *status_labels[i].write().unwrap() = format!("Waiting for other to connect...");
                                // Note: We need to put a timeout() around accept() because otherwise we would wait for an
                                //       eternity for the client to connect when the client won't connect because punching on
                                //       their side hasn't succeeded:
                                match tokio::time::timeout(Duration::from_millis(QUIC_SERVER_ACCEPT_TIMEOUT), quic_server_endpoint.accept()).await {
                                    Ok(Some(quic_connecting)) => {
                                        *status_labels[i].write().unwrap() = format!("Other is connecting...");
                                        match quic_connecting.await {
                                            Ok(quic_connection) => {
                                                match quic_connection.accept_bi().await {
                                                    Ok((mut quic_send_stream, mut quic_receive_stream)) => {
                                                        // (B) localhost TCP client
                                                        //     (simulating the external client and connecting to the localhost server being exposed):
                                                        if let Ok(tcp_stream) = TcpStream::connect(("127.0.0.1", localhost_port_shared)).await {
                                                            let (mut tcp_read_stream, mut tcp_write_stream) = tcp_stream.into_split();

                                                            // Link (A) and (B) together using two new tasks
                                                            //   and join the two in order to continue the loop and start re-punching when either the
                                                            //   global QUIC connection or the local TCP connection fails/is terminated:
                                                            let receive_task = tokio_runtime_clone_2.spawn(async move {
                                                                // Write everything to our TCP client that we receive via QUIC:
                                                                println!("writing test: server software writes to local TCP server");
                                                                tokio::io::copy(&mut "test: server software writes to local TCP server".as_ref(), &mut tcp_write_stream).await.unwrap();
                                                                tokio::io::copy(&mut quic_receive_stream, &mut tcp_write_stream).await.unwrap();
                                                            });
                                                            let send_task = tokio_runtime_clone_3.spawn(async move {
                                                                // Write everything to our QUIC server that we receive from our TCP client:
                                                                println!("writing test: server software writes to QUIC stream");
                                                                tokio::io::copy(&mut "test: server software writes to QUIC stream".as_ref(), &mut quic_send_stream).await.unwrap();
                                                                tokio::io::copy(&mut tcp_read_stream, &mut quic_send_stream).await.unwrap();
                                                            });
                                                            *status_labels[i].write().unwrap() = format!("Connected");
                                                            let _ = tokio::join!(send_task, receive_task); // When both fail/terminate, the punching process will be started again...
                                                            *status_labels[i].write().unwrap() = format!("Connection lost");
                                                        } else {
                                                            *status_labels[i].write().unwrap() = format!("Conn to 127.0.0.1:{} failed", localhost_port_shared);
                                                        }
                                                    },
                                                    Err(err) => {
                                                        *status_labels[i].write().unwrap() = format!("Accepting bi stream from QUIC client failed: {}", err);
                                                    }
                                                }
                                            },
                                            Err(err) => {
                                                *status_labels[i].write().unwrap() = format!("Connecting to QUIC client failed: {}", err);
                                            }
                                        }
                                    },
                                    Ok(None) => {
                                        *status_labels[i].write().unwrap() = format!("Accepting conn failed");
                                    },
                                    Err(err) => {
                                        *status_labels[i].write().unwrap() = format!("Accepting conn failed due to timeout: {}", err);
                                    }
                                }
                            },
                            Err(err) => {
                                *status_labels[i].write().unwrap() = format!("Creating QUIC server endpoint failed: {}", err);
                            }
                        }
                    }
                }
            });
        } 
    }
}

fn pem_file_to_rustls_certificates(cert_path: &std::path::Path) -> Result<Vec<rustls::Certificate>, std::io::Error> {
    //return Ok(rustls::Certificate(std::fs::read(path)?)); // This is right for .der files but wrong for .pem files!

    // Copied from https://github.com/quinn-rs/quinn/blob/main/quinn/examples/server.rs:
    let cert_chain = std::fs::read(cert_path)?; // failed to read certificate chain
    let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
        vec![rustls::Certificate(cert_chain)]
    } else {
        rustls_pemfile::certs(&mut &*cert_chain)? // invalid PEM-encoded certificate
            .into_iter()
            .map(rustls::Certificate)
            .collect()
    };

    return Ok(cert_chain);
}

fn pem_file_to_rustls_private_key(key_path: &std::path::Path) -> Result<rustls::PrivateKey, std::io::Error> {
    //return Ok(rustls::PrivateKey(std::fs::read(path)?)); // This is right for .der files but wrong for .pem files!

    // Copied from https://github.com/quinn-rs/quinn/blob/main/quinn/examples/server.rs:
    let key = std::fs::read(key_path)?; // failed to read private key
    let key = if key_path.extension().map_or(false, |x| x == "der") {
        rustls::PrivateKey(key)
    } else {
        let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)?; // malformed PKCS #8 private key
        match pkcs8.into_iter().next() {
            Some(x) => rustls::PrivateKey(x),
            None => {
                let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)?; // malformed PKCS #1 private key
                match rsa.into_iter().next() {
                    Some(x) => rustls::PrivateKey(x),
                    None => {
                        return Err(std::io::Error::new(std::io::ErrorKind::Other, "no private keys found"));
                    }
                }
            }
        }
    };

    return Ok(key);
}

/// Tries to punch a hole using UDP hole punching to the address behind the
/// specified UDP socket.
/// Returns true when the punch appears to have been successful from our side.
/// Returns false when no packet was received, i.e., when the punch appears to
/// have been unsuccessful; in that case, simply try again.
///
/// This function blocks for a maximum of 9 seconds:
/// * This function waits until the next multiple of 5 seconds, i.e., hole
///   punching is always performed at xx:xx:00, xx:xx:05, xx:xx:10, xx:xx:15,
///   xx:xx:20, xx:xx:25, xx:xx:30, xx:xx:35, xx:xx:40, xx:xx:45, xx:xx:50
///   or xx:xx:55 exactly.
/// * This function then waits for a response packet for up to 4 seconds
///   (timeout).
async fn punch_hole(socket: &UdpSocket) -> Result<bool, tokio::io::Error> { // ToDo: acknowledge with ACKPUNCHes
    // Clear up old punch messages/UDP datagrams from previous punches or punch attempts:
    let mut buffer_for_irrelevant_old_data = [0; 64];
    while let Ok(_) = socket.try_recv(&mut buffer_for_irrelevant_old_data) {
        // (do nothing with the old messages, just read and discard them)
    } // From the docs: "When there is no pending data, Err(io::ErrorKind::WouldBlock) is returned."

    // Calculate punch time:
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let punch_time = Duration::from_millis((((now.as_millis() as f64)/PUNCH_INTERVAL_IN_MILLIS).ceil() * PUNCH_INTERVAL_IN_MILLIS) as u64);

    // Calculate punch message; the one being sent *as well as* the one being expected from the other peer:
    let punch_message = PUNCH_MESSAGE_PREFIX.to_string() + &punch_time.as_secs().to_string();
    // Note: we are including the punch time in the punch message to ensure that a punch message coming from an older
    //       non-successful punch attempt cannot interfere!
    //       Otherwise this may lead to a lifelock and endless alternating punch attempts between two peers!
    
    // Wait until punch time:
    while SystemTime::now().duration_since(UNIX_EPOCH).unwrap() < punch_time {
        // wait...
    }
    // Note: you might be tempted to use tokio::time::sleep(punch_time-now), or even better tokio::time::sleep_until(punch_time), here;
    //       however busy waiting is more accurate and we need it to be accurate in order for UDP hole punching to work!
    //       cf. quote from documentation of tokio::time::sleep():
    //       "[...] should not be used for tasks that require high-resolution timers.
    //        [...] some platforms (specifically Windows) will provide timers with a larger resolution than 1 ms."

    // Punch:
    socket.send(punch_message.as_ref()).await?;

    // On a synchronous std::net::UdpSocket we would now do the following before calling .recv():
    // socket.set_read_timeout(Some(Duration::from_millis(PUNCH_TIMEOUT))).expect("punching failed: set_read_timeout() failed");
    // A tokio::net::UdpSocket however has no such method, instead use tokio::time::timeout
    // (cf. https://github.com/tokio-rs/tokio/issues/510):

    let mut buf = [0; 64];
    if let Ok(Ok(number_of_bytes)) = tokio::time::timeout(Duration::from_millis(PUNCH_TIMEOUT), socket.recv(&mut buf)).await {
        let filled_buf = &mut buf[..number_of_bytes];
        return Ok(String::from_utf8(filled_buf.to_vec()) == Ok(punch_message));
        // returns true when the expected punch message (with the correct timestamp) was received
    } else {
        return Ok(false); // no response after timeout: punch failed (this time)
    }
}
