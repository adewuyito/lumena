#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    token, Address, Env, Map, Symbol, Val, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidWeight = 3,
    InvalidThreshold = 4,
    InvalidAmount = 5,
    UnknownSigner = 6,
    DuplicateSigner = 7,
    ThresholdNotMet = 8,
    InsufficientBalance = 9,
    ContractNotAllowed = 10,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Signers,
    Threshold,
    /// Optional per-contract allowlist. When present, the account only
    /// authorises invocations targeting contracts in this set.
    AllowedContracts,
}

#[contract]
pub struct SmartAccount;

#[contractimpl]
impl SmartAccount {
    /// Stores the weighted signer set. The threshold must be reachable by the
    /// combined weight of all signers so the account can never be bricked.
    pub fn init(env: Env, signers: Map<Address, u32>, threshold: u32) -> Result<(), Error> {
        let storage = env.storage().instance();
        if storage.has(&DataKey::Signers) {
            return Err(Error::AlreadyInitialized);
        }

        // Weights are summed in u64 so no combination of u32 weights can overflow.
        let mut total_weight: u64 = 0;
        let mut signer_count: u32 = 0;
        for (_, weight) in signers.iter() {
            if weight == 0 {
                return Err(Error::InvalidWeight);
            }
            total_weight += weight as u64;
            signer_count += 1;
        }
        if threshold == 0 || total_weight < threshold as u64 {
            return Err(Error::InvalidThreshold);
        }

        storage.set(&DataKey::Signers, &signers);
        storage.set(&DataKey::Threshold, &threshold);

        event_schema::publish(
            &env,
            Symbol::new(&env, "smart_account"),
            Symbol::new(&env, "init"),
            &env.current_contract_address(),
            (signer_count, threshold),
        );
        Ok(())
    }

    /// Transfers `amount` of `token` out of the account once every approver has
    /// authorized the call and their combined weight meets the threshold.
    ///
    /// The approvers are recorded as the invocation's signatures, so the
    /// weighted check is enforced by `__check_auth` like any other call.
    pub fn transfer(
        env: Env,
        approvers: Vec<Address>,
        token: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let account = env.current_contract_address();
        account.require_auth();

        let client = token::Client::new(&env, &token);
        if client.balance(&account) < amount {
            return Err(Error::InsufficientBalance);
        }
        client.transfer(&account, &to, &amount);

        event_schema::publish(
            &env,
            Symbol::new(&env, "smart_account"),
            Symbol::new(&env, "transfer"),
            &account,
            (token, to, amount),
        );
        Ok(())
    }

    /// Invokes `fn_name` on `contract` with `args` on behalf of the account.
    /// The weighted signer threshold (and the optional allowlist) is enforced
    /// by `__check_auth` for the resulting authorisation.
    pub fn invoke(
        env: Env,
        contract: Address,
        fn_name: Symbol,
        args: Vec<Val>,
    ) -> Result<Val, Error> {
        env.current_contract_address().require_auth();
        Ok(env.invoke_contract(&contract, &fn_name, args))
    }

    pub fn signers(env: Env) -> Map<Address, u32> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Map::new(&env))
    }

    pub fn threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .unwrap_or(0)
    }

    /// Sets (or clears) the optional per-contract allowlist. Only the account
    /// itself may change it, so it must be authorised by the weighted signers.
    pub fn set_allowed_contracts(env: Env, contracts: Option<Vec<Address>>) -> Result<(), Error> {
        env.current_contract_address().require_auth();
        let storage = env.storage().instance();
        if !storage.has(&DataKey::Signers) {
            return Err(Error::NotInitialized);
        }
        match contracts {
            Some(contracts) => storage.set(&DataKey::AllowedContracts, &contracts),
            None => storage.remove(&DataKey::AllowedContracts),
        }
        Ok(())
    }

    /// Returns the configured allowlist, or `None` when every contract is allowed.
    pub fn allowed_contracts(env: Env) -> Option<Vec<Address>> {
        env.storage().instance().get(&DataKey::AllowedContracts)
    }
}

impl CustomAccountInterface for SmartAccount {
    type Signature = Vec<Address>;
    type Error = Error;

    /// Weighted multi-sig authorisation for any contract invocation made on
    /// behalf of this account. Every signature must be a known signer, the
    /// combined weight must reach the threshold, and — when an allowlist is
    /// configured — every invoked contract must be on it.
    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        signatures: Vec<Address>,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let storage = env.storage().instance();
        let signers: Map<Address, u32> = storage
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)?;
        let threshold: u32 = storage
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)?;

        let mut seen: Map<Address, bool> = Map::new(&env);
        let mut approved_weight: u64 = 0;
        for signer in signatures.iter() {
            if seen.contains_key(signer.clone()) {
                return Err(Error::DuplicateSigner);
            }
            let weight = signers.get(signer.clone()).ok_or(Error::UnknownSigner)?;
            signer.require_auth();
            seen.set(signer, true);
            approved_weight += weight as u64;
        }
        if approved_weight < threshold as u64 {
            return Err(Error::ThresholdNotMet);
        }

        if let Some(allowed) = storage.get::<_, Vec<Address>>(&DataKey::AllowedContracts) {
            for context in auth_contexts.iter() {
                let contract = match context {
                    Context::Contract(c) => c.contract,
                    Context::CreateContractHostFn(_) | Context::CreateContractWithCtorHostFn(_) => {
                        return Err(Error::ContractNotAllowed)
                    }
                };
                if !allowed.contains(&contract) {
                    return Err(Error::ContractNotAllowed);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
