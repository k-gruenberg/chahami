#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use std::collections::HashMap;
use core::time::Duration;

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

const MAX_NUMBER_OF_PEERS: usize = 10;

struct ChahamiApp {
    my_global_ip_address: String,
    port_shared: String,
    peer_ip_addresses_and_ports: [(String, u16); MAX_NUMBER_OF_PEERS],
    status_labels: [String; MAX_NUMBER_OF_PEERS],
}

impl Default for ChahamiApp {
    fn default() -> Self {
        Self {
            my_global_ip_address: get_my_global_ip_address().unwrap_or("?????".to_owned()),
            port_shared: "".to_owned(),
            peer_ip_addresses_and_ports: Default::default(),
            status_labels: Default::default(),
        }
    }
}

impl eframe::App for ChahamiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Chahami");

            ui.label(format!("Your global IP address: {}", &mut self.my_global_ip_address));
            
            ui.horizontal(|ui| {
                let my_port_label = ui.label("The port you share: ");
                ui.style_mut().spacing.text_edit_width = 50.0;
                ui.text_edit_singleline(&mut self.port_shared)
                    .labelled_by(my_port_label.id);
            });

            ui.label(format!("Your peers:"));
            for i in 0..MAX_NUMBER_OF_PEERS {
                ui.horizontal(|ui| {
                    ui.style_mut().spacing.text_edit_width = 125.0;
                    ui.text_edit_singleline(&mut self.peer_ip_addresses_and_ports[i].0);
                    ui.label(format!("{}", self.status_labels[i]));
                });
            }

            ui.label("Do NOT close this window!");
        });
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
