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
const PUNCH_MESSAGE: &str = "PUNCH"; // the message sent when punching; completely irrelevant
const QUIC_SERVER_SETUP_TIME_IN_MILLIS: u64 = 3_000; // the time that the QUIC client will wait until trying to connect to the QUIC server
const QUIC_SERVER_ACCEPT_TIMEOUT: u64 = 10_000; // the time that the QUIC server will wait for an connection before timing out; has to be larger than QUIC_SERVER_SETUP_TIME_IN_MILLIS!
const ERROR_MESSAGE_DISPLAY_TIME_IN_MILLIS: u64 = 3_000; // the amount of time to display an error message to the user

fn main() {
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(320.0, 350.0)),
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
                        first_loop_iteration = false;
                    }

                    let mut counter = 0;
                    *status_labels[i].write().unwrap() = format!("Punching...");
                    // Try punching (and punching (and punching ...)):
                    loop {
                        match punch_hole(IpAddr::from_str(&peer_ip_address).unwrap(), CHAHAMI_PORT + (i as u16)).await {
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

                    if port_shared.trim() == "" { // We are a client peer: Build a s2n_quic::Client:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        // Wait a little before starting the QUIC client such that the other peer may start its QUIC server:
                        tokio::time::sleep(Duration::from_millis(QUIC_SERVER_SETUP_TIME_IN_MILLIS)).await;

                        // (A) QUIC client (code taken from example on https://crates.io/crates/s2n-quic):
                        let quic_client = match s2n_quic::Client::builder()
                            .with_tls(quic_server_cert_file_path_clone.as_path()).unwrap()
                            .with_io(("0.0.0.0", CHAHAMI_PORT + (i as u16))).unwrap()
                            .start() {
                                Ok(quic_client) => quic_client,
                                Err(err) => {
                                    *status_labels[i].write().unwrap() = format!("Fatal: Couldn't start QUIC client: {}", err);
                                    return; // return from the whole async block to stop handling this peer entirely; do *NOT* continue to try punching
                                }
                            };
                        let addr: SocketAddr = format!("{}:{}", peer_ip_address, CHAHAMI_PORT + (i as u16)).parse().unwrap();
                        let connect = s2n_quic::client::Connect::new(addr).with_server_name("chahami");
                        match quic_client.connect(connect).await {
                            Ok(mut quic_connection) => {
                                quic_connection.keep_alive(true).unwrap(); // Ensure the connection doesn't time out with inactivity
                                let quic_stream = quic_connection.open_bidirectional_stream().await.unwrap();
                                let (mut quic_receive_stream, mut quic_send_stream) = quic_stream.split();

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
                                        *status_labels[i].write().unwrap() = format!("Local TCP conn lost");
                                        // ...the punching process will be started again...
                                    }
                                    Err(err) => {
                                        *status_labels[i].write().unwrap() = format!("Accepting local conn failed: {}", err);
                                    }
                                }
                            },
                            Err(err) => { // e.g. MaxHandshakeDurationExceeded
                                *status_labels[i].write().unwrap() = format!("Conn to QUIC server failed: {}", err);
                            }
                        }
                    } else { // We are a server peer: Build a s2n_quic::Server:
                        // (B) Open up TCP socket and (A) link to QUIC socket:

                        let localhost_port_shared: u16 = port_shared.parse().expect("invalid port number");

                        // (A) QUIC server (code taken from example on https://crates.io/crates/s2n-quic):
                        let mut quic_server = match s2n_quic::Server::builder()
                            .with_tls((quic_server_cert_file_path_clone.as_path(), quic_server_key_file_path_clone.as_path())).unwrap()
                            .with_io(("0.0.0.0", CHAHAMI_PORT + (i as u16))).unwrap()
                            .start() {
                                Ok(quic_server) => quic_server,
                                Err(err) => {
                                    *status_labels[i].write().unwrap() = format!("Fatal: Couldn't start QUIC server: {}", err);
                                    return; // return from the whole async block to stop handling this peer entirely; do *NOT* continue to try punching
                                }
                            };
                        // Wait for other peer (QUIC client) to connect:
                        *status_labels[i].write().unwrap() = format!("Waiting for other to connect");
                        // Note: We need to put a timeout() around accept() because otherwise we would wait for an
                        //       eternity for the client to connect when the client won't connect because punching on
                        //       their side hasn't succeeded:
                        if let Ok(Some(mut quic_connection)) = tokio::time::timeout(Duration::from_millis(QUIC_SERVER_ACCEPT_TIMEOUT), quic_server.accept()).await {
                            let quic_stream = quic_connection.accept_bidirectional_stream().await.unwrap().unwrap();
                            let (mut quic_receive_stream, mut quic_send_stream) = quic_stream.split();

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
                        } else {
                            *status_labels[i].write().unwrap() = format!("Accepting conn failed / timeout");
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
async fn punch_hole(ip_addr: IpAddr, port: u16) -> Result<bool, tokio::io::Error> {
    // Prepare UDP socket:
    let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    socket.connect((ip_addr, port)).await?;

    // Calculate punch time:
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let punch_time = Duration::from_millis((((now.as_millis() as f64)/PUNCH_INTERVAL_IN_MILLIS).ceil() * PUNCH_INTERVAL_IN_MILLIS) as u64);
    
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
    socket.send(PUNCH_MESSAGE.as_ref()).await?;

    // On a synchronous std::net::UdpSocket we would now do the following before calling .recv():
    // socket.set_read_timeout(Some(Duration::from_millis(PUNCH_TIMEOUT))).expect("punching failed: set_read_timeout() failed");
    // A tokio::net::UdpSocket however has no such method, instead use tokio::time::timeout
    // (cf. https://github.com/tokio-rs/tokio/issues/510):

    let mut buf = [0; 64];
    if let Ok(Ok(number_of_bytes)) = tokio::time::timeout(Duration::from_millis(PUNCH_TIMEOUT), socket.recv(&mut buf)).await {
        let filled_buf = &mut buf[..number_of_bytes];
        return Ok(String::from_utf8(filled_buf.to_vec()) == Ok(PUNCH_MESSAGE.to_owned()));
        // returns true when the expected PUNCH_MESSAGE was received
    } else {
        return Ok(false); // no response after timeout: punch failed (this time)
    }
}
