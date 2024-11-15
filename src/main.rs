pub mod commands;
pub mod modules;
pub mod utils;

use std::{
    env,
    process::exit,
    io::IsTerminal
};

use owo_colors::OwoColorize;

use commands::{
    scan::initialize_scan,
    encrypt::initialize_encrypt,
    decrypt::initialize_decrypt
};

use utils::{
    logger::*,
    args::ARGS,
    constants::*,
    statics::LOGGER
};

fn header(color: bool) {
    match color {
        true => {
            println!("{}","-------------------------------------".bright_blue());
            println!("{}{}  {}","__   __".cyan().bold(),"_____".cyan().bold(),"_____".cyan());
            println!("{} {}{}","\\ \\ / /".cyan().bold(),"___ \\".cyan().bold(),"/  ___|".cyan());
            println!(" {}{}{}","\\ V /".cyan().bold(),"| |_/ /".cyan().bold(),"\\ `--.  ___ __ _ _ __".cyan());
            println!("  {} {}  {}","\\ /".cyan().bold(),"|  __/".cyan().bold(),"`--. \\/ __/ _` | '_ \\".cyan());
            println!("  {} {}    {}","| |".cyan().bold(),"| |".cyan().bold(),"/\\__/ / (_| (_| | | | |".cyan());
            println!("  {} {}    {}","\\_/".cyan().bold(),"\\_|".cyan().bold(),"\\____/ \\___\\__,_|_| |_|".cyan());
            println!("");
            println!("  {} {}{}", "Lite".cyan().bold(), "v".cyan(),VERSION.cyan());
            println!("");
            println!("  {} {}", "Made by".cyan().bold(), "Ibrahim Alzamil".cyan());
            println!("{}","-------------------------------------".bright_blue());
            println!("");
        }
        false => {
            println!("-------------------------------------");
            println!("__   _______  _____");
            println!("\\ \\ / / ___ \\/  ___|");
            println!(" \\ V /| |_/ /\\ `--.  ___ __ _ _ __");
            println!("  \\ / |  __/  `--. \\/ __/ _` | '_ \\");
            println!("  | | | |    /\\__/ / (_| (_| | | | |");
            println!("  \\_/ \\_|    \\____/ \\___\\__,_|_| |_|");
            println!("");
            println!("  {} {}{}", "Lite", "v", VERSION);
            println!("");
            println!("  {}", "Made by Ibrahim Alzamil");
            println!("-------------------------------------");
            println!("");
        }
    }
}

fn display_header_and_set_color(color: bool){
    // check if these arguments are set so we don't display header and color
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--json-output".to_string()) || args.contains(&"--no-output".to_string()) || args.contains(&"--csv-output".to_string()) {
        return;
    }

    // Set logger color
    let mut lock = LOGGER.write().unwrap();
    lock.set_color(color);
    drop(lock);
    
    // Display header
    header(color);
}

fn initialize(){
    // Check all logger related arguments and modify logger for each change
    if ARGS.get_flag("debug") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Debug);
        drop(lock);
    }
    if ARGS.get_flag("trace") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Trace);
        drop(lock);
    }
    if ARGS.get_flag("only-alerts") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Alert);
        drop(lock);
    }
    if ARGS.get_flag("no-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtoconsole(false);
        drop(lock);
    }
    if ARGS.get_flag("csv-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logconsoletype(OutputType::CSV);
        drop(lock);
    }
    if ARGS.get_flag("json-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logconsoletype(OutputType::JSON);
        drop(lock);
    }
    if ARGS.get_flag("no-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtofile(false);
        drop(lock);
    }
    if ARGS.get_flag("csv-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfiletype(OutputType::CSV);
        drop(lock);
    }
    if ARGS.get_flag("json-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfiletype(OutputType::JSON);
        drop(lock);
    }
    if ARGS.get_flag("ansi-encoding") && !std::io::stdout().is_terminal() {
        let mut lock = LOGGER.write().unwrap();
        lock.set_ansi(true);
        drop(lock);
    }
    match &ARGS.subcommand_name() {
        Some("scan") => initialize_scan(),
        Some("encrypt") => initialize_encrypt(),
        Some("decrypt") => initialize_decrypt(),
        _ => {
            // Unreachable code
            LOGFATAL!("Clap failed to manage arguments");
            exit(2);
        }
    }
}

fn main() {
    let mut color: bool;
    
    // Try to enable ansi support
    match enable_ansi_support::enable_ansi_support() {
        Ok(_) => {
            // ANSI escape codes were successfully enabled, or this is a non-Windows platform.
            color = true;
        }
        Err(_) => {
            // The operation was unsuccessful, typically because it's running on an older
            // version of Windows. The program may choose to disable ANSI color code output in
            // this case.
            color = false;
        }
    }
    
    // Check if we are not in tty
    if !std::io::stdout().is_terminal() {
        // Disable color
        color = false;
        // Disable progress
        let mut lock = LOGGER.write().unwrap();
        lock.set_logprogress(false);
        drop(lock);
    }

    // Check if color is disabled
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--no-color".to_string()) {
        color = false;
    }

    // Save color settings and display header
    display_header_and_set_color(color);

    // Drop variables to save bits of memory #worth
    let _ = args;
    let _ = color;

    // Start clap and parse arguments
    initialize();
}