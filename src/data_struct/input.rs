use std::io;

pub fn read_line(buffer: &mut String) {
    io::stdin().read_line(buffer).expect("Failed to read line");
}

pub trait InputSource {
    fn read_line(&mut self, prompt: &str) -> String;
    fn read_password(&mut self, prompt: &str) -> String;
}

pub struct InputSourceImpl;

impl InputSource for InputSourceImpl {
    fn read_line(&mut self, prompt: &str) -> String {
        eprintln!("{}", prompt);
        let mut s = String::new();
        read_line(&mut s);
        s.trim().to_string()
    }

    fn read_password(&mut self, prompt: &str) -> String {
        rpassword::prompt_password(prompt).unwrap()
    }
}

#[cfg(test)]
pub struct MockInput {
    pub lines: Vec<String>,
}

#[cfg(test)]
impl InputSource for MockInput {
    fn read_line(&mut self, _prompt: &str) -> String {
        self.lines.remove(0)
    }

    fn read_password(&mut self, _prompt: &str) -> String {
        self.lines.remove(0)
    }
}
