extern crate gtk;

use gtk::traits::*;

fn main() {
    if !gtk::init_check() {
        println!("Cannot start because GTK is not working / available");
        return;
    }

    match gtk::Window::new(gtk::WindowType::TopLevel) {
        None => println!("Unable to create a GTK window."),
        Some(window) => {
            window.set_title("Rubbem");
            window.set_window_position(gtk::WindowPosition::Center);

            window.connect_delete_event(|_, _| {
                gtk::main_quit();
                gtk::signal::Inhibit(false)
            });

            window.show_all();
            gtk::main();
        }
    }
}
