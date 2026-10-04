//! Test helper for `scripts/cli-e2e.sh` (not part of the SDK): creates SPL
//! Token / Token-2022 test mints and reads token balances over JSON-RPC.
//!
//! ```text
//! spl_test_util <rpc> create-mint <payer.json> <spl|token2022> <decimals> <holder> <base units>
//! spl_test_util <rpc> balance <token account> <spl|token2022>
//! spl_test_util <rpc> ata <owner> <mint> <spl|token2022>
//! ```

use qshield_client::rpc::{JsonRpc, Rpc};
use qshield_vault::instruction::build::create_ata_idempotent;
use qshield_vault::token::{self, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

fn program(s: &str) -> Pubkey {
    match s {
        "spl" => TOKEN_PROGRAM,
        "token2022" => TOKEN_2022_PROGRAM,
        _ => panic!("token program must be spl or token2022"),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let rpc = JsonRpc::new(a[1].clone());
    match a[2].as_str() {
        "create-mint" => {
            let payer = read_keypair_file(&a[3]).expect("payer keypair");
            let p = program(&a[4]);
            let decimals: u8 = a[5].parse().unwrap();
            let holder: Pubkey = a[6].parse().unwrap();
            let amount: u64 = a[7].parse().unwrap();
            let mint = Keypair::new();
            let rent = rpc
                .minimum_balance_for_rent_exemption(token::MINT_LEN)
                .unwrap();
            let mut init = vec![20, decimals];
            init.extend_from_slice(payer.pubkey().as_ref());
            init.push(0);
            let ata = token::associated_token_address(&holder, &mint.pubkey(), &p);
            let mut mint_to = vec![14];
            mint_to.extend_from_slice(&amount.to_le_bytes());
            mint_to.push(decimals);
            let ixs = [
                solana_system_interface::instruction::create_account(
                    &payer.pubkey(),
                    &mint.pubkey(),
                    rent,
                    token::MINT_LEN as u64,
                    &p,
                ),
                Instruction::new_with_bytes(p, &init, vec![AccountMeta::new(mint.pubkey(), false)]),
                create_ata_idempotent(&payer.pubkey(), &holder, &mint.pubkey(), &p),
                Instruction::new_with_bytes(
                    p,
                    &mint_to,
                    vec![
                        AccountMeta::new(mint.pubkey(), false),
                        AccountMeta::new(ata, false),
                        AccountMeta::new_readonly(payer.pubkey(), true),
                    ],
                ),
            ];
            let bh = rpc.latest_blockhash().unwrap();
            let msg = Message::new_with_blockhash(&ixs, Some(&payer.pubkey()), &bh);
            let tx = Transaction::new(&[&payer, &mint], msg, bh);
            rpc.send_and_confirm(&tx.into()).unwrap();
            println!("{}", mint.pubkey());
        }
        "balance" => {
            let addr: Pubkey = a[3].parse().unwrap();
            let p = program(&a[4]);
            let amount = match rpc.get_account(&addr).unwrap() {
                Some(acct) => token::parse_token_account(&p, &acct.data).unwrap().amount,
                None => 0,
            };
            println!("{amount}");
        }
        "ata" => {
            let owner: Pubkey = a[3].parse().unwrap();
            let mint: Pubkey = a[4].parse().unwrap();
            println!(
                "{}",
                token::associated_token_address(&owner, &mint, &program(&a[5]))
            );
        }
        _ => panic!("unknown command"),
    }
}
