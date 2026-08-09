// Release/.exe: без чёрного окна консоли. Debug (`cargo run`) — консоль остаётся для логов.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(e) = p2p_messenger::run_native() {
        eprintln!("VOID: {e}");
        std::process::exit(1);
    }
}
