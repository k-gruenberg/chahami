#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use eframe::egui::Color32;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::{RwLock, Arc};
use std::net::{IpAddr, SocketAddr};
use tokio::net::{UdpSocket, TcpListener, TcpStream};
use std::str::FromStr;

const MAX_NUMBER_OF_PEERS: usize = 10;
const CHAHAMI_PORT: u16 = 13137; // 3137 == 0xc41 (as in "ChAhamI")
const PUNCH_INTERVAL_IN_MILLIS: f64 = 5_000.0; // the punch time is every 5,000 milliseconds
const PUNCH_TIMEOUT: u64 = 4_000; // after having punched, wait 4,000 milliseconds for a response until considering the punch as a failure
const PUNCH_MESSAGE: &str = "PUNCH"; // the message sent when punching; completely irrelevant
const QUIC_SERVER_SETUP_TIME_IN_MILLIS: u64 = 2_000; // the time that the QUIC client will wait until trying to connect to the QUIC server

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(290.0, 350.0)),
        ..Default::default()
    };
    eframe::run_native(
        "Chahami",
        options,
        Box::new(|_cc| Box::new(ChahamiApp::default())),
    );
}

struct ChahamiApp {
    tokio_runtime: Arc<tokio::runtime::Runtime>,
    my_global_ip_address: String,
    port_shared: String,
    peer_ip_addresses: [String; MAX_NUMBER_OF_PEERS],
    status_labels: Arc<[RwLock<String>; MAX_NUMBER_OF_PEERS]>,
    gone: bool, // = whether the "Go!" button has been clicked
}

impl Default for ChahamiApp {
    fn default() -> Self {
        Self {
            tokio_runtime: Arc::new(tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()),
            my_global_ip_address: get_my_global_ip_address().unwrap_or("?????".to_owned()),
            port_shared: "".to_owned(),
            peer_ip_addresses: Default::default(),
            status_labels: Default::default(),
            gone: false,
        }
    }
}

impl eframe::App for ChahamiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Chahami");

            ui.label(format!("Your global IP address: {}", &mut self.my_global_ip_address));
            
            let port_shared_is_valid: bool = self.port_shared.parse::<u16>().is_ok();
            ui.horizontal(|ui| {
                let my_port_label = ui.label("The port you share: ");
                ui.style_mut().spacing.text_edit_width = 50.0;
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.port_shared)
                    .interactive(!self.gone) // disables editing once "Go!" has been pressed
                    .text_color(if port_shared_is_valid {Color32::LIGHT_GREEN} else {Color32::RED})
                );
                response.labelled_by(my_port_label.id);
            });

            ui.label(format!("Your peers:"));
            for i in 0..MAX_NUMBER_OF_PEERS {
                ui.horizontal(|ui| {
                    ui.style_mut().spacing.text_edit_width = 125.0;
                    let ip_addr_is_valid = IpAddr::from_str(&self.peer_ip_addresses[i]).is_ok();
                    ui.add(
                        egui::TextEdit::singleline(&mut self.peer_ip_addresses[i])
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
                    if self.port_shared.trim() == "" || port_shared_is_valid {
                        self.gone = true;
                        go(
                            self.tokio_runtime.clone(),
                            self.port_shared.clone(),
                            self.peer_ip_addresses.clone(),
                            self.status_labels.clone()
                        );
                    }
                }
            }

            ui.label("Do NOT close this window!");
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
    for i in 0..MAX_NUMBER_OF_PEERS {
        if peer_ip_addresses[i].trim() != "" { // For each peer the user specified:
            let port_shared = port_shared.clone();
            let peer_ip_address = peer_ip_addresses[i].clone();
            let status_labels = status_labels.clone();
            let tokio_runtime_clone_1 = tokio_runtime.clone();
            let tokio_runtime_clone_2 = tokio_runtime.clone();
            let tokio_runtime_clone_3 = tokio_runtime.clone();
            tokio_runtime_clone_1.spawn(async move { // Note: punching will be performed concurrently, which has both its upsides and its downsides...
                loop { // Looping to restart punching when the QUIC connection fails (initially or sometime later):
                    let mut counter = 0;
                    *status_labels[i].write().unwrap() = format!("Punching...");
                    // Try punching (and punching (and punching ...)):
                    while !punch_hole(IpAddr::from_str(&peer_ip_address).unwrap()).await {
                        counter += 1;
                        *status_labels[i].write().unwrap() = format!("Punching failed {} times", counter);
                    }
                    *status_labels[i].write().unwrap() = format!("Punching succeeded");

                    // After punching succeeded, (A) connect using QUIC and (B) start localhost forwarding:
                    if port_shared.trim() == "" { // We are a client peer: Build a s2n_quic::Client:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        // (A) QUIC client (code taken from example on https://crates.io/crates/s2n-quic):
                        // Wait a little such that the other peer may start its QUIC server:
                        tokio::time::sleep(Duration::from_millis(QUIC_SERVER_SETUP_TIME_IN_MILLIS)).await;
                        let client = s2n_quic::Client::builder()
                            .with_io(("0.0.0.0", CHAHAMI_PORT)).unwrap()
                            .start().unwrap();
                        let addr: SocketAddr = format!("{}:{}", peer_ip_address, CHAHAMI_PORT).parse().unwrap();
                        let connect = s2n_quic::client::Connect::new(addr).with_server_name("chahami");
                        let mut connection = client.connect(connect).await.unwrap();
                        connection.keep_alive(true).unwrap(); // Ensure the connection doesn't time out with inactivity
                        let stream = connection.open_bidirectional_stream().await.unwrap();
                        let (mut quic_receive_stream, mut quic_send_stream) = stream.split();

                        // (B) localhost TCP server (to which the client application will connect):
                        let addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap(); // Port number = 0 means OS will assign a port
                        let listener = TcpListener::bind(&addr).await.unwrap();

                        // Display the user the address of the local TCP proxy to connect to:
                        *status_labels[i].write().unwrap() = format!("{:?}", listener.local_addr());

                        // Now wait for the user to connect:
                        let (tcp_stream, _remote_peer) = listener.accept().await.unwrap();
                        // One needs to use .into_split() as suggested on https://github.com/tokio-rs/tokio-core/issues/198:
                        let (mut tcp_read_stream, mut tcp_write_stream) = tcp_stream.into_split();

                        // Link (A) and (B) together using two new tasks
                        //   and join the two in order to continue the loop and start re-punching when either the
                        //   global QUIC connection or the local TCP connection fails/is terminated:
                        let receive_task = tokio_runtime_clone_2.spawn(async move {
                            // Write everything to our TCP client that we receive via QUIC:
                            tokio::io::copy(&mut quic_receive_stream, &mut tcp_write_stream).await.unwrap();
                        });
                        let send_task = tokio_runtime_clone_3.spawn(async move {
                            // Write everything to our QUIC server that we receive from our TCP client:
                            tokio::io::copy(&mut tcp_read_stream, &mut quic_send_stream).await.unwrap();
                        });

                        let _ = tokio::join!(send_task, receive_task); // When both fail/terminate, the punching process will be started again... 
                    } else { // We are a server peer: Build a s2n_quic::Server:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        let localhost_port_shared: u16 = port_shared.parse().expect("invalid port number");

                        // (A) QUIC server (code taken from example on https://crates.io/crates/s2n-quic):
                        let quic_server_cert: &[u8] = include_bytes!("../quic_server_cert.pem");
                        let quic_server_key: &[u8] = include_bytes!("../quic_server_key.pem");
                        let mut server = s2n_quic::Server::builder()
                            .with_tls((quic_server_cert, quic_server_key)).unwrap()
                            .with_io(("0.0.0.0", CHAHAMI_PORT)).unwrap()
                            .start().unwrap();
                        // Wait for other peer (QUIC client) to connect:
                        *status_labels[i].write().unwrap() = format!("Waiting for other to connect");
                        if let Some(mut connection) = server.accept().await {
                            let stream = connection.open_bidirectional_stream().await.unwrap();
                            let (mut quic_receive_stream, mut quic_send_stream) = stream.split();

                            // (B) localhost TCP client
                            //     (simulating the external client and connecting to the localhost server being exposed):
                            let tcp_stream = TcpStream::connect(("127.0.0.1", localhost_port_shared)).await.unwrap();
                            let (mut tcp_read_stream, mut tcp_write_stream) = tcp_stream.into_split();

                            // Link (A) and (B) together using two new tasks
                            //   and join the two in order to continue the loop and start re-punching when either the
                            //   global QUIC connection or the local TCP connection fails/is terminated:
                            let receive_task = tokio_runtime_clone_2.spawn(async move {
                                // Write everything to our TCP client that we receive via QUIC:
                                tokio::io::copy(&mut quic_receive_stream, &mut tcp_write_stream).await.unwrap();
                            });
                            let send_task = tokio_runtime_clone_3.spawn(async move {
                                // Write everything to our QUIC server that we receive from our TCP client:
                                tokio::io::copy(&mut tcp_read_stream, &mut quic_send_stream).await.unwrap();
                            });
                            *status_labels[i].write().unwrap() = format!("Connected");
                            let _ = tokio::join!(send_task, receive_task); // When both fail/terminate, the punching process will be started again...
                            *status_labels[i].write().unwrap() = format!("Connection lost");
                        } else {
                            *status_labels[i].write().unwrap() = format!("Accepting conn failed");
                        }
                    }
                }
            });
        } 
    }
}

/// Tries to punch a hole using UDP hole punching to the specified address
/// (IP address + port).
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
async fn punch_hole(ip_addr: IpAddr) -> bool {
    // Prepare UDP socket:
    let socket = UdpSocket::bind(("0.0.0.0", CHAHAMI_PORT))
        .await
        .expect("punching failed: couldn't bind to address 0.0.0.0:CHAHAMI_PORT");
    socket.connect((ip_addr, CHAHAMI_PORT)).await.expect("connect function failed");

    // Calculate punch time:
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let punch_time = Duration::from_millis((((now.as_millis() as f64)/PUNCH_INTERVAL_IN_MILLIS).ceil() * PUNCH_INTERVAL_IN_MILLIS) as u64);
    
    // Wait until punch time:
    while SystemTime::now().duration_since(UNIX_EPOCH).unwrap() < punch_time {
        // wait...
    }

    // Punch:
    socket.send(PUNCH_MESSAGE.as_ref()).await.expect("punching failed: couldn't send data");

    // On a synchronous std::net::UdpSocket we would now do the following before calling .recv():
    // socket.set_read_timeout(Some(Duration::from_millis(PUNCH_TIMEOUT))).expect("punching failed: set_read_timeout() failed");
    // A tokio::net::UdpSocket however has no such method, instead use tokio::time::timeout
    // (cf. https://github.com/tokio-rs/tokio/issues/510):

    let mut buf = [0; 64];
    if let Ok(Ok(number_of_bytes)) = tokio::time::timeout(Duration::from_millis(PUNCH_TIMEOUT), socket.recv(&mut buf)).await {
        let filled_buf = &mut buf[..number_of_bytes];
        return String::from_utf8(filled_buf.to_vec()) == Ok(PUNCH_MESSAGE.to_owned());
        // returns true when the expected PUNCH_MESSAGE was received
    } else {
        return false; // no response after timeout: punch failed (this time)
    }
}
