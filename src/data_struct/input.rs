use std::io;

pub fn read_line(buffer: &mut String) {
    io::stdin().read_line(buffer).expect("Failed to read line");
}

pub trait InputSource {
    fn read_line(&mut self, prompt: &str) -> String;
    fn read_password(&mut self, prompt: &str) -> String;
    fn read_line_with_default(&mut self, prompt: &str, default: &str) -> String {
        let input = self.read_line(prompt);
        if input.is_empty() {
            default.to_string()
        } else {
            input
        }
    }

    fn prompt_for_confirmation(&mut self, prompt: &str) -> bool {
        let input = self.read_line(prompt);
        let input = input.trim().to_lowercase();
        input == "y" || input == "yes"
    }
}

pub struct InputSourceImpl;

impl InputSource for InputSourceImpl {
    fn read_line(&mut self, prompt: &str) -> String {
        eprint!("{}", prompt);
        let mut s = String::new();
        read_line(&mut s);
        s.trim().to_string()
    }

    fn read_password(&mut self, prompt: &str) -> String {
        rpassword::prompt_password(prompt).unwrap()
    }
}

#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct MockInput {
    pub lines: Vec<String>,
}

#[cfg(any(test, feature = "test-util"))]
impl InputSource for MockInput {
    fn read_line(&mut self, _prompt: &str) -> String {
        self.lines.remove(0)
    }

    fn read_password(&mut self, _prompt: &str) -> String {
        self.lines.remove(0)
    }
}
