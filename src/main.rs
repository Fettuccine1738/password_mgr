use std::io::{self, BufRead};

use pass_man::{
    add_password, create_new_vault,
    data_struct::{UnlockedVault, input::InputSourceImpl},
    load_vault_files, sign_into_vault,
};

const MAIN_PROMPT: &str = "What would you like to do? \n\
                               1. Create a new password vault \n\
                               2. Sign in to a password vault \n\
                               3. Add a password to a vault \n\
                               4. Fetch a password from a vault \n\
                               NOTE: If you have previously signed in, no need to sign in again.
                              ";

fn run_cli() {
    print_banner();
    loop {
        let _ = prompt();
    }
}

fn prompt() -> Result<(), std::io::Error> {
    let mut input: String = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let input = input.trim();
    let mut input_src = InputSourceImpl;

    if input == "1" {
        // create new vault
        let current_vault: UnlockedVault = create_new_vault(&mut input_src);
    } else if input == "2" {
        // sign in to  a new password vault
        let current_vault = todo!(); // sign_into_vault();
    } else if input == "3" {
        // prompt for sign name, password and allow record insertion
        add_password(todo!(), todo!());
    } else if input == "4" {
        // fetch record if not signed in yet.
        todo!()
    } else {
        let input = &input.to_lowercase();
        if input == "q" || input == "quit" || input == "Quit" {
            // clean up
            eprintln!("exiting.....");
            std::process::exit(0);
        } else if input == "signout" {
            eprintln!("Signing out of current vault");
        }

        eprintln!("[{input}] not recognized.");
        println!("{}", MAIN_PROMPT);
    }

    Ok(())
}

fn print_banner() {
    println!(
        r#"
 ____                                    _   __  __
|  _ \ __ _ ___ _____      _____  _ __ __| | |  \/  | __ _ _ __
| |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` | | |\/| |/ _` | '__|
|  __/ (_| \__ \__ \\ V  V / (_) | | | (_| | | |  | | (_| | |
|_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_| |_|  |_|\__, |_|
                                                       |___/
"#
    );
}

fn main() {
    print_banner();
    println!("=================================");
    println!("         PasswordManager");
    println!("=================================");
    let vault_cache = load_vault_files().unwrap();

    loop {
        println!("{}", MAIN_PROMPT);
        println!("Found {} Vaults.", vault_cache.0.len());
        let _ = prompt();
    }
}
