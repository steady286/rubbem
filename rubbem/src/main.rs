extern crate gtk;

use gtk::traits::*;

fn main() {
    match gtk::init() {
        Err(_) => println!("Cannot start because GTK is not working / available."),
        Ok(_) => gtk_main()
    }
}

fn gtk_main()
{
    match gtk::Window::new(gtk::WindowType::TopLevel) {
        None => println!("Unable to create a GTK window."),
        Some(window) => gtk_window(window)
    }
}

fn gtk_window(window: gtk::Window)
{
    window.set_title("Rubbem");
    window.set_window_position(gtk::WindowPosition::Center);

    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::signal::Inhibit(false)
    });

    window.show_all();
    gtk::main();
}

