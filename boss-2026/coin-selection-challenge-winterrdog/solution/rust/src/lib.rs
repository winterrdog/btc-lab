use rust_decimal::Decimal;
use serde_json::Value;
use serde::Deserialize;
use std::process::Command;

#[derive(Deserialize)]
pub struct Payment {
    pub address: String,
    #[serde(with = "rust_decimal::serde::float")]
    pub amount: Decimal,
    #[serde(with = "rust_decimal::serde::float")]
    pub rate: Decimal
}

#[derive(Deserialize)]
struct Coin {
    // Will be read and written as JSON to and from bitcoin-cli
    // so no need to parse as bytes or reverse byte-order.
    pub txid: String,

    pub vout: u64,

    // Could also use scriptPubKey but it might be easier
    // to determine required spending conditions from an address.
    pub address: String,

    #[serde(with = "rust_decimal::serde::float")]
    pub amount: Decimal
}

pub fn bcli(cmd: &str) -> String {
    let res = Command::new("bitcoin-cli")
        .arg("-regtest")
        .arg("-rpcuser=student")
        .arg("-rpcpassword=boss2026")
        .args(cmd.split_whitespace())
        .output()
        .expect("bitcoin-cli command failed");
    String::from_utf8_lossy(&res.stdout).to_string()
}

pub fn make_payments(payments: &[Payment]) {
    // Make payments
    for payment in payments {
        // Get all UTXO in wallet coin pool
        let list_unspent = bcli("listunspent");
        // Objectify coins to spend
        let mut coins: Vec<Coin> = serde_json::from_str(&list_unspent).unwrap();


        // Select coins


        // Create transaction
        let mut inputs = String::new();
        let mut outputs = String::new();
        let unsigned_tx = bcli(&format!("createrawtransaction {inputs} {outputs}"));
        // Sign transaction
        let signed_tx_res = bcli(&format!("signrawtransactionwithwallet {unsigned_tx}"));
        let signed_tx_json: Value = serde_json::from_str(&signed_tx_res).unwrap();
        let signed_tx = signed_tx_json["hex"].as_str().unwrap();

        // Broadcast transaction without maxfeerate protection
        bcli(&format!("sendrawtransaction {signed_tx} 0"));

        // Confirm transaciton
        bcli("generatetoaddress 1 bcrt1pqqqqrldkrl");
    }
}
