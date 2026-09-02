use soroban_sdk::{contract, contractimpl, Address, Bytes, Env, String, Vec};

use crate::errors::OracleError;
use crate::merkle;
use crate::storage;
use crate::types::{AssetPrice, BatchPriceEntry, MerkleProof, MultiSigConfig, MultiSigProposal, ProposalAction, PriceDataPoint, SourceReputation};
use crate::utils::{append_history, apply_reputation_decay, calculate_usd_price, deviation_exceeds, update_reputation, vec_contains_address};

// Issue #383 — ABI version of the exported interface.  Bump only for a
// breaking change to any exported entrypoint's shape (see
// docs/CONTRACT_VERSIONING.md); every upgrade keeps this value stable.
pub const API_VERSION: u32 = 1;

#[contract]
pub struct PriceOracleContract;

#[contractimpl]
impl PriceOracleContract {
    /// Version of the exported ABI.  Stable across non-breaking upgrades;
    /// consumers can gate integrations on it.  Also exposed by the proxy.
    pub fn get_api_version(_env: Env) -> u32 {
        API_VERSION
    }

    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError> {
        if storage::has_admin(&env) {
            return Err(OracleError::AlreadyInitialized);
        }
        storage::set_admin(&env, &admin);
        storage::set_storage_layout_version(&env, 1);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #69 — price submission with deviation threshold validation
    // -------------------------------------------------------------------------

    pub fn submit_price(
        env: Env,
        source: Address,
        asset: String,
        price: i128,
        decimals: u32,
        timestamp: u64,
    ) -> Result<PriceDataPoint, OracleError> {
        source.require_auth();

        // Issue #379 — a multi-sig-guarded emergency pause halts submission
        // globally; reads (get_price/get_price_history) remain unaffected so
        // every region keeps serving cached data during the freeze.
        if storage::is_paused(&env) {
            return Err(OracleError::ContractPaused);
        }

        if !storage::is_authorized_source(&env, &source) {
            return Err(OracleError::UnauthorizedSource);
        }
        if price < 0 {
            return Err(OracleError::InvalidPrice);
        }

        // Deviation check: only active when a threshold has been configured and a
        // previous price exists (bypassed for initial submission).
        if let Some(threshold_bps) = storage::get_deviation_threshold(&env) {
            if let Some(prev) = storage::get_latest_price(&env, &asset) {
                if deviation_exceeds(price, prev.price, threshold_bps) {
                    return Err(OracleError::PriceDeviationTooLarge);
                }
            }
        }

        let data_point = PriceDataPoint {
            asset: asset.clone(),
            price,
            decimals,
            timestamp,
            source: source.clone(),
        };

        // Update reputation before overwriting latest price so we still have
        // the previous price available for accuracy comparison.
        update_reputation(&env, &source, price, &asset, timestamp);

        storage::set_latest_price(&env, &asset, &data_point);
        append_history(&env, &asset, data_point.clone());

        env.events()
            .publish(("price_submitted", asset, source), (price, timestamp));

        Ok(data_point)
    }

    // -------------------------------------------------------------------------
    // Issue #75 — Merkle batch submission
    // -------------------------------------------------------------------------

    /// Commit a Merkle root covering a batch of price entries.
    ///
    /// The authorized source submits one transaction with the root hash of an
    /// ordered batch.  Individual entries are applied later via
    /// `apply_batch_entry` using inclusion proofs — one cheap tx per price
    /// instead of one full auth+storage tx per price.
    ///
    /// `nonce` must equal the current BatchNonce (prevents replay attacks).
    /// Returns the new nonce after this batch.
    pub fn submit_batch(
        env: Env,
        source: Address,
        nonce: u64,
        root: Bytes,
    ) -> Result<u64, OracleError> {
        source.require_auth();

        // Issue #379 — batch commits are a submission path too and must
        // honor the same global emergency pause as submit_price.
        if storage::is_paused(&env) {
            return Err(OracleError::ContractPaused);
        }

        if !storage::is_authorized_source(&env, &source) {
            return Err(OracleError::UnauthorizedSource);
        }
        if root.len() != 32 {
            return Err(OracleError::InvalidMerkleProof);
        }
        if nonce != storage::get_batch_nonce(&env) {
            return Err(OracleError::BatchNonceMismatch);
        }

        storage::set_batch_root(&env, nonce, &root);
        let new_nonce = storage::increment_batch_nonce(&env);

        env.events()
            .publish(("batch_submitted", source), (nonce, root));

        Ok(new_nonce)
    }

    /// Apply a single price entry from an already-committed batch.
    ///
    /// The Merkle proof is verified against the stored root; no additional
    /// source auth is required because the root was already committed by an
    /// authorized source.  Anyone can submit proofs — the cryptographic proof
    /// is the authorization.
    pub fn apply_batch_entry(
        env: Env,
        batch_nonce: u64,
        entry: BatchPriceEntry,
        proof: MerkleProof,
    ) -> Result<PriceDataPoint, OracleError> {
        let root =
            storage::get_batch_root(&env, batch_nonce).ok_or(OracleError::BatchRootNotFound)?;

        if entry.price < 0 {
            return Err(OracleError::InvalidPrice);
        }

        if !merkle::verify_proof(&env, &entry, proof.leaf_index, &proof.siblings, &root) {
            return Err(OracleError::InvalidMerkleProof);
        }

        // Issue #385 — each (batch, leaf) pair can be applied exactly once; a
        // repeated apply of an already-applied leaf fails with
        // BatchEntryAlreadyApplied instead of writing a duplicate history entry.
        storage::mark_batch_leaf_applied(&env, batch_nonce, proof.leaf_index)?;

        let data_point = PriceDataPoint {
            asset: entry.asset.clone(),
            price: entry.price,
            decimals: entry.decimals,
            timestamp: entry.timestamp,
            source: entry.source.clone(),
        };

        storage::set_latest_price(&env, &entry.asset, &data_point);
        append_history(&env, &entry.asset, data_point.clone());

        env.events().publish(
            ("batch_entry_applied", entry.asset.clone()),
            (batch_nonce, entry.price),
        );

        Ok(data_point)
    }

    pub fn get_batch_nonce(env: Env) -> u64 {
        storage::get_batch_nonce(&env)
    }

    /// Read-only inclusion check used by off-chain tooling and tests.
    pub fn verify_batch_proof(
        env: Env,
        batch_nonce: u64,
        entry: BatchPriceEntry,
        proof: MerkleProof,
    ) -> bool {
        let Some(root) = storage::get_batch_root(&env, batch_nonce) else {
            return false;
        };
        merkle::verify_proof(&env, &entry, proof.leaf_index, &proof.siblings, &root)
    }

    // -------------------------------------------------------------------------
    // Issue #69 — admin: configure deviation threshold
    // -------------------------------------------------------------------------

    pub fn set_deviation_threshold(
        env: Env,
        admin: Address,
        threshold_bps: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::set_deviation_threshold(&env, threshold_bps);
        Ok(())
    }

    pub fn get_deviation_threshold(env: Env) -> Option<u32> {
        storage::get_deviation_threshold(&env)
    }

    // -------------------------------------------------------------------------
    // Issue #70 — reputation query and admin reset
    // -------------------------------------------------------------------------

    pub fn get_source_reputation(env: Env, source: Address) -> Option<SourceReputation> {
        let rep = storage::get_source_reputation(&env, &source)?;
        Some(apply_reputation_decay(&env, rep))
    }

    pub fn reset_reputation(env: Env, admin: Address, source: Address) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::remove_source_reputation(&env, &source);
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Issue #67 — multi-sig admin control
    // -------------------------------------------------------------------------

    pub fn init_multisig(
        env: Env,
        admin: Address,
        signers: Vec<Address>,
        threshold: u32,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;

        if threshold == 0 || threshold as usize > signers.len() as usize {
            return Err(OracleError::InvalidThreshold);
        }

        let config = MultiSigConfig { signers, threshold };
        storage::set_multisig_config(&env, &config);
        Ok(())
    }

    pub fn create_proposal(
        env: Env,
        proposer: Address,
        action: ProposalAction,
    ) -> Result<u32, OracleError> {
        proposer.require_auth();

        let config =
            storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;

        if !vec_contains_address(&config.signers, &proposer) {
            return Err(OracleError::NotASigner);
        }

        let id = storage::get_msig_proposal_count(&env);
        let mut approvals: Vec<Address> = Vec::new(&env);
        approvals.push_back(proposer.clone());

        let proposal = MultiSigProposal {
            id,
            action,
            approvals,
            executed: 0,
            created_at: env.ledger().timestamp(),
            proposer,
        };

        storage::set_multisig_proposal(&env, &proposal);
        storage::set_proposal_count(&env, id + 1);

        Ok(id)
    }

    pub fn approve_proposal(
        env: Env,
        signer: Address,
        proposal_id: u32,
    ) -> Result<(), OracleError> {
        signer.require_auth();

        let config =
            storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;

        if !vec_contains_address(&config.signers, &signer) {
            return Err(OracleError::NotASigner);
        }

        let mut proposal = storage::get_multisig_proposal(&env, proposal_id)
            .ok_or(OracleError::ProposalNotFound)?;

        if proposal.executed == 1 {
            return Err(OracleError::ProposalAlreadyExecuted);
        }

        if vec_contains_address(&proposal.approvals, &signer) {
            return Err(OracleError::AlreadyApproved);
        }

        proposal.approvals.push_back(signer);
        storage::set_multisig_proposal(&env, &proposal);
        Ok(())
    }

    pub fn execute_proposal(
        env: Env,
        signer: Address,
        proposal_id: u32,
    ) -> Result<(), OracleError> {
        signer.require_auth();

        let config =
            storage::get_multisig_config(&env).ok_or(OracleError::MultiSigNotInitialized)?;

        if !vec_contains_address(&config.signers, &signer) {
            return Err(OracleError::NotASigner);
        }

        let mut proposal = storage::get_multisig_proposal(&env, proposal_id)
            .ok_or(OracleError::ProposalNotFound)?;

        if proposal.executed == 1 {
            return Err(OracleError::ProposalAlreadyExecuted);
        }

        if proposal.approvals.len() < config.threshold {
            return Err(OracleError::ThresholdNotMet);
        }

        apply_proposal_action(&env, &proposal.action)?;

        proposal.executed = 1;
        storage::set_multisig_proposal(&env, &proposal);

        env.events()
            .publish(("governance_executed", signer), proposal_id);

        Ok(())
    }

    pub fn get_proposal(env: Env, proposal_id: u32) -> Option<MultiSigProposal> {
        storage::get_multisig_proposal(&env, proposal_id)
    }

    pub fn get_multisig_config(env: Env) -> Option<MultiSigConfig> {
        storage::get_multisig_config(&env)
    }

    // -------------------------------------------------------------------------
    // Issue #379 — multi-region aware emergency pause
    // -------------------------------------------------------------------------

    /// Read-only pause flag. Off-chain aggregators in every region poll this
    /// on their normal cycle and skip submission while it is `true`, so all
    /// regions honor the freeze within one poll cycle without a separate
    /// off-chain coordination bus — the chain itself is the single source of
    /// truth for pause state.
    pub fn is_paused(env: Env) -> bool {
        storage::is_paused(&env)
    }

    // -------------------------------------------------------------------------
    // Existing oracle functions
    // -------------------------------------------------------------------------

    pub fn get_price(env: Env, asset: String) -> Option<AssetPrice> {
        let data_point = storage::get_latest_price(&env, &asset)?;
        let num_sources = storage::get_source_count(&env);
        let is_trusted = storage::is_trusted_asset(&env, &asset);

        let price_usd = calculate_usd_price(
            &env,
            &data_point.asset,
            data_point.price,
            data_point.decimals,
        );

        Some(AssetPrice {
            asset: data_point.asset,
            price: data_point.price,
            decimals: data_point.decimals,
            price_usd,
            timestamp: data_point.timestamp,
            source: data_point.source,
            num_sources,
            is_trusted,
        })
    }

    pub fn get_assets(env: Env) -> Vec<String> {
        storage::get_all_assets(&env)
    }

    pub fn get_price_history(env: Env, asset: String, limit: u32) -> Vec<PriceDataPoint> {
        let all_history = storage::get_price_history(&env, &asset);
        let len = all_history.len();
        let start = if len > limit { len - limit } else { 0 };
        let mut result: Vec<PriceDataPoint> = Vec::new(&env);
        for i in start..len {
            if let Some(dp) = all_history.get(i) {
                result.push_back(dp);
            }
        }
        result
    }

    // -------------------------------------------------------------------------
    // Issue #376 — TTL / rent extension. Permissionless: bumping TTL is never
    // harmful, and gating it behind auth would only make the scheduled job
    // more brittle. Intended to be called periodically (see docs/RENT_AND_TTL.md)
    // for every tracked asset plus once for the contract instance.
    // -------------------------------------------------------------------------

    pub fn extend_price_history_ttl(env: Env, asset: String, threshold: u32, extend_to: u32) {
        storage::extend_price_history_ttl(&env, &asset, threshold, extend_to);
    }

    pub fn extend_instance_ttl(env: Env, threshold: u32, extend_to: u32) {
        storage::extend_instance_ttl(&env, threshold, extend_to);
    }

    // ── Admin functions ───────────────────────────────────────────────────────

    pub fn add_oracle_source(
        env: Env,
        admin: Address,
        source: Address,
        name: String,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::add_source(&env, &source, &name);
        Ok(())
    }

    pub fn remove_oracle_source(
        env: Env,
        admin: Address,
        source: Address,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::remove_source(&env, &source);
        Ok(())
    }

    pub fn set_trusted_asset(
        env: Env,
        admin: Address,
        asset: String,
        trusted: bool,
    ) -> Result<(), OracleError> {
        admin.require_auth();
        storage::verify_admin(&env, &admin)?;
        storage::set_trusted_asset(&env, &asset, trusted);
        Ok(())
    }

    pub fn set_query_fee(env: Env, fee: i128) {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_query_fee(&env, &fee);
    }

    pub fn get_query_fee(env: Env) -> i128 {
        storage::get_query_fee(&env)
    }

    pub fn set_whitelist(env: Env, addr: Address, status: bool) {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        storage::set_whitelist(&env, &addr, status);
    }

    pub fn withdraw_fees(env: Env, to: Address) {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        let balance = storage::get_fee_balance(&env);
        if balance > 0 {
            storage::set_fee_balance(&env, &0);
            let token = soroban_sdk::token::Client::new(&env, &to);
            token.transfer(&env.current_contract_address(), &to, &balance);
        }
    }

    pub fn stake(env: Env, source: Address, amount: i128, token: Address) {
        source.require_auth();
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&source, &env.current_contract_address(), &amount);
        let current = storage::get_stake(&env, &source);
        storage::set_stake(&env, &source, &(current + amount));
        env.events().publish(("source_staked", source), amount);
    }

    pub fn slash(env: Env, source: Address, amount: i128, reason: String) {
        let admin = storage::get_admin(&env);
        admin.require_auth();
        let current = storage::get_stake(&env, &source);
        let slashed = if amount > current { current } else { amount };
        storage::set_stake(&env, &source, &(current - slashed));
        let count = storage::get_slash_count(&env, &source);
        storage::set_slash_count(&env, &source, &(count + 1));
        env.events()
            .publish(("source_slashed", source, reason), slashed);
    }

    pub fn get_stake_balance(env: Env, source: Address) -> i128 {
        storage::get_stake(&env, &source)
    }

    // -------------------------------------------------------------------------
    // Issue #376 — scheduled TTL / rent extension
    // -------------------------------------------------------------------------

    /// Extend the TTL of every persistent price-history entry plus the
    /// shared instance storage entry (Admin, GovernanceConfig,
    /// GovernanceProposal, MultiSigConfig) so state never expires between
    /// scheduled rent-payment runs. Callable by anyone — it only pays rent
    /// and cannot mutate oracle state, so no admin auth is required.
    pub fn extend_storage_ttl(env: Env) {
        storage::extend_instance_ttl(&env);
        let assets = storage::get_all_assets(&env);
        for i in 0..assets.len() {
            if let Some(asset) = assets.get(i) {
                storage::extend_price_history_ttl(&env, &asset);
            }
        }
    }
}

fn apply_proposal_action(env: &Env, action: &ProposalAction) -> Result<(), OracleError> {
    match action {
        ProposalAction::AddSource(source, name) => {
            storage::add_source(env, source, name);
        }
        ProposalAction::RemoveSource(source) => {
            storage::remove_source(env, source);
        }
        ProposalAction::SetTrustedAsset(asset, trusted) => {
            storage::set_trusted_asset(env, asset, *trusted);
        }
        ProposalAction::TransferAdmin(new_admin) => {
            storage::set_admin(env, new_admin);
        }
        ProposalAction::SetDeviationThreshold(threshold_bps) => {
            storage::set_deviation_threshold(env, *threshold_bps);
        }
        ProposalAction::ResetReputation(source) => {
            storage::remove_source_reputation(env, source);
        }
        ProposalAction::AddSigner(new_signer) => {
            if let Some(mut config) = storage::get_multisig_config(env) {
                if !vec_contains_address(&config.signers, new_signer) {
                    config.signers.push_back(new_signer.clone());
                    storage::set_multisig_config(env, &config);
                }
            }
        }
        ProposalAction::RemoveSigner(signer) => {
            if let Some(mut config) = storage::get_multisig_config(env) {
                let mut new_signers: Vec<Address> = Vec::new(env);
                for i in 0..config.signers.len() {
                    if let Some(s) = config.signers.get(i) {
                        if &s != signer {
                            new_signers.push_back(s);
                        }
                    }
                }
                config.signers = new_signers;
                storage::set_multisig_config(env, &config);
            }
        }
        ProposalAction::SetThreshold(new_threshold) => {
            if let Some(mut config) = storage::get_multisig_config(env) {
                config.threshold = *new_threshold;
                storage::set_multisig_config(env, &config);
            }
        }
        ProposalAction::Pause => {
            storage::set_paused(env, true);
        }
        ProposalAction::Unpause => {
            storage::set_paused(env, false);
        }
        _ => {}
    }
    Ok(())
}

fn vec_contains_address(vec: &Vec<Address>, target: &Address) -> bool {
    for i in 0..vec.len() {
        if let Some(addr) = vec.get(i) {
            if &addr == target {
                return true;
            }
        }
    }
    false
}

fn calculate_usd_price(env: &Env, asset: &String, price: i128, decimals: u32) -> Option<i128> {
    let xlm = String::from_str(env, "XLM");
    if asset == &xlm {
        return Some(price);
    }
    let usdc = String::from_str(env, "USDC");
    if let Some(_usdc_anchor) = storage::get_latest_price(env, &usdc) {
        if asset == &usdc {
            return Some(10i128.pow(decimals));
        }
        if let Some(xlm_price) = storage::get_latest_price(env, &xlm) {
            let base_asset_price =
                (price * xlm_price.price).checked_div(10i128.pow(xlm_price.decimals))?;
            return Some(base_asset_price);
        }
    }
    let xlm_price = storage::get_latest_price(env, &xlm)?;
    // (price_in_xlm * xlm_usd_price) / 10^xlm_price.decimals -- uses
    // xlm_price's own decimals, not usdc_anchor's, since
    // xlm_price.price is scaled by xlm_price.decimals.
    let usd_value = (price * xlm_price.price)
        .checked_div(10i128.pow(xlm_price.decimals))?;
    Some(usd_value)
}
