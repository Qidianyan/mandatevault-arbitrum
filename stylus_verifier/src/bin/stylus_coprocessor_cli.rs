//! Native CLI & IPC entrypoint for `mandate-vault-stylus-verifier`
//! Allows EVM harnesses and cross-language SDK tests to execute the exact compiled
//! Rust Stylus `dispatch_evm_calldata` and RFC 8032 Ed25519 signing routines.

use mandate_vault_stylus_verifier::{
    dispatch_evm_calldata, encode_verify_mandate_call, selector, sign_ap2_digest_ed25519,
};
use std::env;
use std::process;

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    if clean.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: stylus_coprocessor_cli <call <calldataHex> | sign <seed32Hex> <digest32Hex> | selectors>");
        process::exit(2);
    }

    match args[1].as_str() {
        "selectors" => {
            let v_sel = selector("verifyMandate(bytes32,bytes,bytes)");
            let s_sel = selector("verifierScheme()");
            println!(
                "{{\"verifyMandate\":\"{}\",\"verifierScheme\":\"{}\"}}",
                to_hex(&v_sel),
                to_hex(&s_sel)
            );
        }
        "call" => {
            if args.len() < 3 {
                eprintln!("Missing calldataHex");
                process::exit(2);
            }
            let calldata = unhex(&args[2]).unwrap_or_else(|e| {
                eprintln!("Invalid hex: {}", e);
                process::exit(2);
            });
            match dispatch_evm_calldata(&calldata) {
                Ok(ret) => println!("{}", to_hex(&ret)),
                Err(code) => {
                    eprintln!("REVERT:0x{:02x}", code);
                    process::exit(1);
                }
            }
        }
        "sign" => {
            if args.len() < 4 {
                eprintln!("Usage: stylus_coprocessor_cli sign <seed32Hex> <digest32Hex>");
                process::exit(2);
            }
            let seed_vec = unhex(&args[2]).expect("valid seed hex");
            let digest_vec = unhex(&args[3]).expect("valid digest hex");
            if seed_vec.len() != 32 || digest_vec.len() != 32 {
                eprintln!("seed and digest must be 32 bytes");
                process::exit(2);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_vec);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&digest_vec);

            let (pubkey, sig, authorizer) = sign_ap2_digest_ed25519(&seed, &digest);
            let calldata = encode_verify_mandate_call(&digest, &sig, &pubkey);
            println!(
                "{{\"pubkey\":\"{}\",\"signature\":\"{}\",\"authorizer\":\"{}\",\"calldata\":\"{}\"}}",
                to_hex(&pubkey),
                to_hex(&sig),
                to_hex(&authorizer),
                to_hex(&calldata)
            );
        }
        other => {
            eprintln!("Unknown command: {}", other);
            process::exit(2);
        }
    }
}
