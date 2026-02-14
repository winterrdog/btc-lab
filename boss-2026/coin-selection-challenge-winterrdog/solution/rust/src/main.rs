use boss_coin_selection::*;

use std::fs;
use std::path::PathBuf;

fn main() {
    // Create wallet
    bcli("createwallet student false true");
    // Import descriptors
    let student_wallet = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                         .join("..")
                         .join("..")
                         .join("datadir")
                         .join("student_wallet.json");
    let student_wallet_data = fs::read_to_string(student_wallet).unwrap();
    let descriptors: String = student_wallet_data.chars().filter(|c| !c.is_whitespace()).collect();
    bcli(&format!("importdescriptors {descriptors}"));
    // Import payments
    let payments_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("..")
                        .join("..")
                        .join("payments.json");
    let payments_json = fs::read_to_string(payments_file).unwrap();
    let payments: Vec<Payment> = serde_json::from_str(&payments_json).unwrap();
    // Make payments
    make_payments(&payments);
}
