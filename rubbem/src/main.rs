extern crate gtk;
extern crate bm_client;

use gtk::prelude::*;
use bm_client::BMClient;

fn main() {
    let mut bm_client = BMClient::new();
    bm_client.start();

    match gtk::init() {
        Err(_) => println!("Cannot start because GTK is not working / available."),
        Ok(_) => gtk_main()
    }
}

fn gtk_main()
{
    let window = gtk::Window::new(gtk::WindowType::Toplevel);

    window.set_title("Rubbem");
    window.set_position(gtk::WindowPosition::Center);

    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::Inhibit(false)
    });

    window.show_all();
    gtk::main();
}
