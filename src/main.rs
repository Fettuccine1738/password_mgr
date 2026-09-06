use pass_man::{
    create_new_vault,
    data_struct::{
        VaultFiles, VaultState,
        input::{InputSource, InputSourceImpl},
        vc::Secret,
    },
    load_vault_files,
};

const _EXIT_CODE_WRONG_PASSWORD: i32 = 67;
const MAIN_PROMPT: &str = "What would you like to do? \n\
                               1. Create a new password vault \n\
                               2. Sign in to a password vault \n\
                               3. Add a password to a vault \n\
                               4. Fetch a password from a vault \n\
                               5. Sign out of the current vault \n\
                               6. Quit \n\
                               NOTE: If you have previously signed in, no need to sign in again.
                              ";

fn run_cli() {
    print_smol_banner();
    let vault_files = load_vault_files().unwrap();
    let mut vault_state = VaultState::Limbo;
    let mut input_src = InputSourceImpl; // no cost for a 0 sized type, nice for readability
    loop {
        print!("{}", MAIN_PROMPT);
        let _ = prompt(&vault_files, &mut vault_state, &mut input_src);
    }
}

fn print_smol_banner() {
    println!("=================================");
    println!("         PasswordManager");
    println!("=================================");
}

fn prompt(
    _vf: &VaultFiles,
    vault_state: &mut VaultState,
    input_src: &mut impl InputSource,
) -> Result<(), std::io::Error> {
    let input: String = input_src.read_line("Enter number only: ");

    if input == "1" {
        // create new vault
        *vault_state = match create_new_vault(input_src) {
            Some(uv) => {
                eprintln!("Vault created succesfully");
                VaultState::Unlocked(uv)
            }
            None => {
                eprintln!("Could not create vault");
                VaultState::Limbo
            }
        };
    } else if input == "2" {
        // required because rust won't let us leave state unintialized
        // take puts us in Limbo
        let state = std::mem::take(vault_state); // take
        let new_state = VaultState::transition(state, input_src); // modify 
        *vault_state = new_state; // return
    } else if input == "3" {
        // Some of secret's fields are optional, but we will require all of them for now.
        // i.e store a secret not associated with a website, but we will require a name and password.
        // e.g store a secret for a bank account, but not associated with a website.
        if let VaultState::Limbo = *vault_state {
            eprintln!("No unlocked vault, sign in first");
            return Ok(());
        }

        let name = input_src.read_line("Add name or email for secret: ");
        let passw = input_src.read_password("Add password: ");
        let website = input_src.read_line("Add website (without https://): ");

        // validate secret here, easier logic than we can do in Secret::validate,
        //  since we have all the fields here.
        match Secret::validate_and_return(passw, name, website) {
            Ok(s) => {
                if vault_state.add_password(s, input_src) {
                    let _ = vault_state.lock_and_write();
                    eprintln!("Password added successfully");
                } else {
                    eprintln!("Password already exists, not added");
                }
            }
            Err(msg) => eprintln!("Invalid secret: {}", msg),
        };
    } else if input == "4" {
        match VaultState::fetch_password_for_website(vault_state, input_src) {
            Some(secret) => println!("{}", secret), // relies on Secret's Display impl
            None => eprintln!("No unlocked vault, or no match found."),
        }
    } else if input == "5" {
        eprintln!("Signing out of current vault");
        *vault_state = VaultState::Limbo;
    } else {
        let input = &input.to_lowercase();
        if input == "q" || input == "quit" || input == "Quit" {
            // clean up
            // we could be cautious and check if vault_state is Unlocked, and if so, lock it and write it to disk, but we will just exit for now.
            // we prefer to only lock and write when we have a new password, so we don't have to ask for the password again.
            eprintln!("exiting.....");
            std::process::exit(0);
        } else {
            eprintln!("[{input}] not recognized.");
            println!("{}", MAIN_PROMPT);
        }
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
    // use options to decide
    run_cli();
}
