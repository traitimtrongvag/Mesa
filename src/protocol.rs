use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "pubkey")]
    PublicKey { token: String, key: String },
    #[serde(rename = "key_exchange")]
    KeyExchange {
        to: String,
        from: String,
        payload: String,
    },
    #[serde(rename = "msg")]
    ChatMessage {
        to: String,
        from: String,
        n: u64,
        data: String,
    },
    #[serde(rename = "token")]
    Token { token: String },
    #[serde(rename = "clients")]
    ClientList { clients: Vec<String> },
}

impl WsMessage {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn new_token(token: String) -> Self {
        Self::Token { token }
    }

    pub fn new_public_key(token: String, key: String) -> Self {
        Self::PublicKey { token, key }
    }

    pub fn new_key_exchange(to: String, from: String, payload: String) -> Self {
        Self::KeyExchange { to, from, payload }
    }

    pub fn new_chat_message(to: String, from: String, n: u64, data: String) -> Self {
        Self::ChatMessage { to, from, n, data }
    }

    pub fn new_client_list(clients: Vec<String>) -> Self {
        Self::ClientList { clients }
    }
}
