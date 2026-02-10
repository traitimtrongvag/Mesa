use rand::{distributions::Alphanumeric, Rng};

const TOKEN_LENGTH: usize = 10;

pub fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(TOKEN_LENGTH)
        .map(char::from)
        .collect()
}

pub fn is_valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 20
        && token.chars().all(|c| c.is_alphanumeric())
}
