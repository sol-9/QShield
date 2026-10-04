//! Guardian policy (QSP-1 v2, ADR-0018): everyday sends within a limit or to
//! saved addresses, guardian approval for everything else, freeze and
//! recovery. All instant — nothing is queued on a timer.

use qshield_mldsa::SIGNATURE_LEN;
use qshield_protocol::v2::{ActionV2, AuthorizationV2, Role};
use qshield_protocol::{AssetType, ZERO32};
use qshield_vault::instruction::build;
use qshield_vault::state::{KeyState, Policy, Proposal};
use qshield_vault::token;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;

use crate::client::{AuthOptions, MintAccount, Transport, VaultInfo, CHUNK, EXECUTE_CU_LIMIT};
use crate::envelope::Hints;
use crate::key::verify_authorization;
use crate::rpc::Rpc;
use crate::{Error, QShieldClient};

const SYSTEM_PROGRAM: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// What the everyday key can do alone right now for a SOL send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendPath {
    /// One transaction, everyday key only.
    Instant,
    /// Needs a guardian approval (propose, then approve).
    NeedsGuardian,
}

impl<R: Rpc> QShieldClient<R> {
    /// Guardian policy PDA of a vault.
    pub fn policy_address(&self, vault: &Pubkey) -> Pubkey {
        build::policy_address(&self.program_id, vault).0
    }

    /// Reads the vault's policy (None if the vault never had one).
    pub fn get_policy(&self, vault: &Pubkey) -> Result<Option<Policy>, Error> {
        match self.rpc.get_account(&self.policy_address(vault))? {
            Some(a) if a.owner == self.program_id => Policy::load(&a.data)
                .map(Some)
                .map_err(|_| Error::Account("invalid policy account".into())),
            _ => Ok(None),
        }
    }

    /// Reads a proposal.
    pub fn get_proposal(&self, vault: &Pubkey, id: u64) -> Result<Option<Proposal>, Error> {
        let addr = build::proposal_address(&self.program_id, vault, id).0;
        match self.rpc.get_account(&addr)? {
            Some(a) if a.owner == self.program_id && a.lamports > 0 => Proposal::load(&a.data)
                .map(Some)
                .map_err(|_| Error::Account("invalid proposal account".into())),
            _ => Ok(None),
        }
    }

    /// Whether a SOL send of `lamports` (plus `fee`) to `to` can go out now
    /// with the everyday key alone (refill computed at `now`).
    pub fn sol_send_path(
        &self,
        policy: &Policy,
        to: &Pubkey,
        lamports: u64,
        fee: u64,
        now: i64,
    ) -> SendPath {
        let mut p = *policy;
        p.refill(now);
        let need = fee.saturating_add(if p.is_saved(&to.to_bytes()) {
            0
        } else {
            lamports
        });
        if need <= p.available {
            SendPath::Instant
        } else {
            SendPath::NeedsGuardian
        }
    }

    /// Base v2 authorization for this program and cluster.
    pub fn v2_base(
        &self,
        vault: &Pubkey,
        role: Role,
        nonce: u64,
        action: ActionV2,
        opts: &AuthOptions,
    ) -> AuthorizationV2 {
        AuthorizationV2 {
            cluster_id: self.cluster_id,
            program_id: self.program_id.to_bytes(),
            vault: vault.to_bytes(),
            action,
            asset_type: AssetType::None,
            nonce,
            valid_after: opts.valid_after,
            expires_at: opts.expires_at,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: if opts.fee_lamports > 0 {
                opts.fee_recipient.map(|p| p.to_bytes()).unwrap_or(ZERO32)
            } else {
                ZERO32
            },
            fee_lamports: opts.fee_lamports,
            new_key_id: ZERO32,
            new_algorithm: 0,
            role,
            ref_id: 0,
            limit_lamports: 0,
            limit_period: 0,
        }
    }

    /// The nonce the given role must sign with now.
    pub fn role_nonce(&self, vault: &VaultInfo, role: Role) -> Result<u64, Error> {
        match role {
            Role::Everyday => Ok(vault.state.nonce),
            Role::Guardian => self
                .get_policy(&vault.address)?
                .filter(|p| p.enabled)
                .map(|p| p.guardian_nonce)
                .ok_or_else(|| Error::Account("the vault has no guardian policy".into())),
        }
    }

    /// Transfer fields (SOL or SPL to the owner's associated token account).
    /// Returns the authorization and the hints to submit it.
    #[allow(clippy::too_many_arguments)]
    pub fn v2_transfer(
        &self,
        vault: &Pubkey,
        role: Role,
        nonce: u64,
        action: ActionV2,
        mint: Option<&MintAccount>,
        to_owner: &Pubkey,
        amount: u64,
        opts: &AuthOptions,
    ) -> (AuthorizationV2, Hints) {
        let base = self.v2_base(vault, role, nonce, action, opts);
        match mint {
            None => (
                AuthorizationV2 {
                    asset_type: AssetType::Sol,
                    destination: to_owner.to_bytes(),
                    amount,
                    ..base
                },
                Hints::default(),
            ),
            Some(m) => (
                AuthorizationV2 {
                    asset_type: m.asset_type,
                    mint: m.address.to_bytes(),
                    destination: token::associated_token_address(
                        to_owner,
                        &m.address,
                        &m.token_program,
                    )
                    .to_bytes(),
                    amount,
                    decimals: m.info.decimals,
                    ..base
                },
                Hints {
                    destination_owner: Some(to_owner.to_string()),
                    ..Hints::default()
                },
            ),
        }
    }

    /// The guardian approval restating a proposal's exact effect.
    pub fn approval_for(
        &self,
        vault: &Pubkey,
        guardian_nonce: u64,
        p: &Proposal,
        opts: &AuthOptions,
    ) -> Result<AuthorizationV2, Error> {
        Ok(AuthorizationV2 {
            asset_type: AssetType::from_u8(p.asset_type)
                .ok_or_else(|| Error::Account("bad proposal asset".into()))?,
            mint: p.mint,
            destination: p.destination,
            amount: p.amount,
            decimals: p.decimals,
            ref_id: p.id,
            ..self.v2_base(
                vault,
                Role::Guardian,
                guardian_nonce,
                ActionV2::ApproveWithdraw,
                opts,
            )
        })
    }

    /// Accounts after `[fee_payer, vault, signer_key, policy]` (PROTOCOL §5).
    fn v2_action_accounts(
        &self,
        a: &AuthorizationV2,
        vault: &VaultInfo,
        policy: Option<&Policy>,
        hints: &Hints,
    ) -> Result<Vec<AccountMeta>, Error> {
        use ActionV2::*;
        let w = |k: Pubkey| AccountMeta::new(k, false);
        let vault_addr = vault.address;
        let hint_key = |what: &str| -> Result<Pubkey, Error> {
            hints
                .new_key_account
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidInput(format!(
                        "{what} needs the key account (hint new_key_account)"
                    ))
                })?
                .parse()
                .map_err(|_| Error::InvalidInput("bad key account".into()))
        };
        let transfer = |a: &AuthorizationV2| -> Result<Vec<AccountMeta>, Error> {
            if a.asset_type == AssetType::Sol {
                return Ok(vec![w(Pubkey::new_from_array(a.destination))]);
            }
            let program = token::program_for(a.asset_type)
                .ok_or_else(|| Error::InvalidInput("bad asset".into()))?;
            let mint = Pubkey::new_from_array(a.mint);
            let source = match &hints.source_token_account {
                Some(s) => s
                    .parse()
                    .map_err(|_| Error::InvalidInput("bad source".into()))?,
                None => token::associated_token_address(&vault_addr, &mint, &program),
            };
            Ok(build::withdraw_spl_accounts(
                &source,
                &mint,
                &Pubkey::new_from_array(a.destination),
                &program,
                None,
            ))
        };
        let proposal = |id: u64| build::proposal_address(&self.program_id, &vault_addr, id).0;
        let mut accts = match a.action {
            WithdrawSol | WithdrawSpl => transfer(a)?,
            ProposeWithdraw => vec![
                w(proposal(a.nonce)),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            ApproveWithdraw | CancelProposal => {
                let p = self
                    .get_proposal(&vault_addr, a.ref_id)?
                    .ok_or_else(|| Error::Account(format!("proposal {} not found", a.ref_id)))?;
                let mut v = vec![
                    w(proposal(a.ref_id)),
                    w(Pubkey::new_from_array(p.rent_payer)),
                ];
                if a.action == ApproveWithdraw {
                    v.extend(transfer(a)?);
                }
                v
            }
            RotateKey => {
                let new = hint_key("RotateKey")?;
                let old = self.get_key_account(&Pubkey::new_from_array(vault.state.key_account))?;
                vec![
                    w(new),
                    w(old.address),
                    w(Pubkey::new_from_array(old.header.creator)),
                ]
            }
            RotateGuardian => {
                let new = hint_key("RotateGuardian")?;
                let p = policy.ok_or_else(|| Error::Account("no policy".into()))?;
                let old = self.get_key_account(&Pubkey::new_from_array(p.guardian_key_account))?;
                vec![w(new), w(Pubkey::new_from_array(old.header.creator))]
            }
            EnablePolicy => vec![
                w(hint_key("EnablePolicy")?),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            Pause | Unpause | SetLimit | AddAddress | RemoveAddress | DisablePolicy => vec![],
        };
        if a.fee_lamports > 0 && a.fee_recipient != ZERO32 {
            accts.push(w(Pubkey::new_from_array(a.fee_recipient)));
        }
        Ok(accts)
    }

    /// Submits a signed v2 authorization. Checks locally first (cluster,
    /// program, the role's nonce, the signature against the role's current
    /// key, key accounts named in hints) so invalid submissions cost nothing.
    pub fn submit_v2(
        &self,
        fee_payer: &Keypair,
        auth_bytes: &[u8],
        signature: &[u8],
        hints: &Hints,
        transport: Transport,
    ) -> Result<Vec<Signature>, Error> {
        if signature.len() != SIGNATURE_LEN {
            return Err(Error::InvalidInput("signature must be 2,420 bytes".into()));
        }
        let a = AuthorizationV2::decode(auth_bytes).map_err(Error::Protocol)?;
        if a.cluster_id != self.cluster_id || a.program_id != self.program_id.to_bytes() {
            return Err(Error::InvalidInput(
                "authorization is for another cluster or program".into(),
            ));
        }
        let vault_addr = Pubkey::new_from_array(a.vault);
        let vault = self.get_vault(&vault_addr)?;
        let policy = self.get_policy(&vault_addr)?.filter(|p| p.enabled);
        let (signer_key, nonce) = match a.role {
            Role::Everyday => (
                Pubkey::new_from_array(vault.state.key_account),
                vault.state.nonce,
            ),
            Role::Guardian => {
                let p = policy
                    .as_ref()
                    .ok_or_else(|| Error::Account("the vault has no guardian policy".into()))?;
                (
                    Pubkey::new_from_array(p.guardian_key_account),
                    p.guardian_nonce,
                )
            }
        };
        if nonce != a.nonce {
            return Err(Error::InvalidInput(format!(
                "authorization nonce {} but the {:?} nonce is {nonce}",
                a.nonce, a.role
            )));
        }
        let key = self.get_key_account(&signer_key)?;
        if !verify_authorization(&key.public_key, auth_bytes, signature) {
            return Err(Error::InvalidInput(format!(
                "signature is not valid for the vault's current {:?} key",
                a.role
            )));
        }
        if let Some(k) = &hints.new_key_account {
            let k: Pubkey = k
                .parse()
                .map_err(|_| Error::InvalidInput("bad key account".into()))?;
            let h = self.get_key_account(&k)?.header;
            if h.key_id != a.new_key_id || h.state != KeyState::Ready {
                return Err(Error::Account(
                    "key account is not ready for this key id".into(),
                ));
            }
        }
        let accts = self.v2_action_accounts(&a, &vault, policy.as_ref(), hints)?;
        // Create the recipient's token account first if needed (paid by the fee payer).
        let mut pre: Vec<Instruction> = vec![];
        if a.asset_type != AssetType::Sol
            && a.asset_type != AssetType::None
            && matches!(a.action, ActionV2::WithdrawSpl | ActionV2::ApproveWithdraw)
        {
            if let (Some(owner), Some(program)) =
                (&hints.destination_owner, token::program_for(a.asset_type))
            {
                let owner: Pubkey = owner
                    .parse()
                    .map_err(|_| Error::InvalidInput("bad owner".into()))?;
                let dest = Pubkey::new_from_array(a.destination);
                let mint = Pubkey::new_from_array(a.mint);
                if token::associated_token_address(&owner, &mint, &program) != dest {
                    return Err(Error::InvalidInput(
                        "destination is not the owner's token account".into(),
                    ));
                }
                if self.rpc.get_account(&dest)?.is_none() {
                    pre.push(build::create_ata_idempotent(
                        &fee_payer.pubkey(),
                        &owner,
                        &mint,
                        &program,
                    ));
                }
            }
        }
        match transport {
            Transport::Inline => {
                let ix = build::execute_v2(
                    &self.program_id,
                    &fee_payer.pubkey(),
                    &vault_addr,
                    &signer_key,
                    &accts,
                    auth_bytes,
                    signature,
                );
                pre.push(ix);
                Ok(vec![self.send_v1(&pre, fee_payer, EXECUTE_CU_LIMIT)?])
            }
            Transport::Buffered => {
                let mut sigs = vec![];
                let buf = self.upload_signature(fee_payer, &vault_addr, signature, &mut sigs)?;
                let ix = build::execute_v2_with_buffer(
                    &self.program_id,
                    &fee_payer.pubkey(),
                    &vault_addr,
                    &signer_key,
                    &buf,
                    &fee_payer.pubkey(),
                    &accts,
                    auth_bytes,
                );
                pre.push(ix);
                match self.legacy3(&pre, fee_payer, Some(EXECUTE_CU_LIMIT)) {
                    Ok(s) => {
                        sigs.push(s);
                        Ok(sigs)
                    }
                    Err(e) => {
                        let _ = self.legacy3(
                            &[build::close_sig_buffer(
                                &self.program_id,
                                &fee_payer.pubkey(),
                                &buf,
                            )],
                            fee_payer,
                            None,
                        );
                        Err(e)
                    }
                }
            }
        }
    }

    /// Legacy transaction paid and signed by `payer` alone.
    fn legacy3(
        &self,
        ixs: &[Instruction],
        payer: &Keypair,
        cu: Option<u32>,
    ) -> Result<Signature, Error> {
        self.send_legacy(ixs, payer, &[], cu)
    }

    /// Uploads a signature into a fresh buffer (legacy transactions).
    pub(crate) fn upload_signature(
        &self,
        fee_payer: &Keypair,
        vault: &Pubkey,
        signature: &[u8],
        sigs: &mut Vec<Signature>,
    ) -> Result<Pubkey, Error> {
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).map_err(|_| Error::RandomnessUnavailable)?;
        let id = u64::from_le_bytes(id);
        let (buf, _) = build::sig_buffer_address(&self.program_id, vault, &fee_payer.pubkey(), id);
        sigs.push(self.legacy3(
            &[build::create_sig_buffer(
                &self.program_id,
                &fee_payer.pubkey(),
                vault,
                id,
            )],
            fee_payer,
            None,
        )?);
        let n = signature.len().div_ceil(CHUNK);
        for (i, chunk) in signature.chunks(CHUNK).enumerate() {
            let ix = build::write_sig_buffer(
                &self.program_id,
                &fee_payer.pubkey(),
                &buf,
                (i * CHUNK) as u16,
                i + 1 == n,
                chunk,
            );
            match self.legacy3(&[ix], fee_payer, None) {
                Ok(s) => sigs.push(s),
                Err(e) => {
                    let _ = self.legacy3(
                        &[build::close_sig_buffer(
                            &self.program_id,
                            &fee_payer.pubkey(),
                            &buf,
                        )],
                        fee_payer,
                        None,
                    );
                    return Err(e);
                }
            }
        }
        Ok(buf)
    }

    /// Closes a dead proposal (expired, its key replaced, or no policy).
    pub fn close_proposal(
        &self,
        payer: &Keypair,
        vault: &Pubkey,
        id: u64,
    ) -> Result<Signature, Error> {
        let p = self
            .get_proposal(vault, id)?
            .ok_or_else(|| Error::Account("no such proposal".into()))?;
        let addr = build::proposal_address(&self.program_id, vault, id).0;
        self.legacy3(
            &[build::close_proposal(
                &self.program_id,
                vault,
                &addr,
                &Pubkey::new_from_array(p.rent_payer),
            )],
            payer,
            None,
        )
    }
}
