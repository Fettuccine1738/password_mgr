use std::io::{self, BufRead};

use pass_man::{add_password, create_new_vault, data_struct::UnlockedVault, get_password, sign_into_vault};

// fn main() {
//     let mut input = String::new();
//     io::stdin()
//         .read_line(&mut input)
//         .expect("Failed to read line");

//     let input = input.trim(); // remove trailing newline
//     println!("You entered: {}", input);
// }

const PROMPT_START_UP: &str = "What would you like to do? \n\
                               1. Create a new password vault \n\
                               2. Sign in to a password vault \n\
                               3. Add a password to a vault \n\
                               4. Fetch a password from a vault \n\
                               NOTE: If you have previously signed in, no need to 
                               sign in again.
                              ";

fn prompt() -> Result<(), std::io::Error> {
    let mut input: String = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let input = input.trim();

    if input == "1" {
        // create new vault
        let current_vault: UnlockedVault = create_new_vault();
    } else if input == "2" {
        // sign in to  a new password vault
        let current_vault = sign_into_vault();
    } else if input == "3" {
        // prompt for sign name, password and allow record insertion
        add_password(todo!(), todo!());
    } else if input == "4" {
        // fetch record if not signed in yet.
        get_password();
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
        println!("{}", PROMPT_START_UP);
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
    println!("{}", PROMPT_START_UP);
    let _ = prompt();
}
