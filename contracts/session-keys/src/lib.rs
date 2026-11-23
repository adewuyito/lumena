#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Vec};

/// A temporary session key delegation registered by an account owner.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionKey {
    /// Ledger timestamp (seconds) after which the key is no longer valid.
    pub valid_until: u64,
    /// Contracts the session key is allowed to call.
    pub allowed_contracts: Vec<Address>,
    /// Methods the session key is allowed to invoke.
    pub allowed_methods: Vec<Symbol>,
    /// Maximum cumulative amount the session key may spend.
    pub max_cumulative_amount: i128,
    /// Amount already spent by the session key.
    pub cumulative_spent: i128,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Keyed by (owner, session_key).
    Session(Address, Address),
    /// Index: session_key -> owner (for validate lookup).
    OwnerIndex(Address),
    /// Maximum session key lifetime in seconds, configured at init.
    MaxTtl,
}

/// Semantic version of this contract, kept in sync with `Cargo.toml`.
pub const CONTRACT_VERSION: u32 = 1;

#[contract]
pub struct SessionKeysContract;

#[contractimpl]
impl SessionKeysContract {
    /// Returns the contract version.
    pub fn version(_env: Env) -> u32 {
        CONTRACT_VERSION
    }

    /// Configure the maximum session key lifetime, in seconds.
    pub fn initialize(env: Env, max_ttl: u64) {
        if env.storage().instance().has(&DataKey::MaxTtl) {
            panic!("session keys already initialized");
        }
        env.storage().instance().set(&DataKey::MaxTtl, &max_ttl);
    }

    /// Register a new session key for `owner`. Requires owner authorization.
    pub fn register_session_key(
        env: Env,
        owner: Address,
        session_key: Address,
        valid_until: u64,
        allowed_contracts: Vec<Address>,
        allowed_methods: Vec<Symbol>,
        max_cumulative_amount: i128,
    ) {
        owner.require_auth();

        let key = DataKey::Session(owner.clone(), session_key.clone());
        if env.storage().persistent().has(&key) {
            panic!("session key already registered");
        }

        // Reject expiries beyond the configured maximum lifetime.
        let now = env.ledger().timestamp();
        let max_ttl: u64 = env
            .storage()
            .instance()
            .get(&DataKey::MaxTtl)
            .unwrap_or(u64::MAX);
        if valid_until > now.saturating_add(max_ttl) {
            panic!("session key expiry exceeds max_ttl");
        }

        let record = SessionKey {
            valid_until,
            allowed_contracts,
            allowed_methods,
            max_cumulative_amount,
            cumulative_spent: 0,
        };

        env.storage().persistent().set(&key, &record);
        // Write reverse index so validate_session_call can find the owner.
        env.storage()
            .persistent()
            .set(&DataKey::OwnerIndex(session_key.clone()), &owner);

        event_schema::publish(
            &env,
            Symbol::new(&env, "session_keys"),
            Symbol::new(&env, "register"),
            &owner,
            (session_key, valid_until),
        );
    }

    /// Revoke an existing session key. Requires owner authorization.
    pub fn revoke_session_key(env: Env, owner: Address, session_key: Address) {
        owner.require_auth();

        let key = DataKey::Session(owner.clone(), session_key.clone());
        if !env.storage().persistent().has(&key) {
            panic!("session key not found");
        }
        env.storage().persistent().remove(&key);
        env.storage()
            .persistent()
            .remove(&DataKey::OwnerIndex(session_key.clone()));

        event_schema::publish(
            &env,
            Symbol::new(&env, "session_keys"),
            Symbol::new(&env, "revoke"),
            &owner,
            session_key,
        );
    }

    /// Validate a call made by `session_key` against `target` invoking `method`
    /// with `amount`. Returns `true` if allowed and updates cumulative spend.
    pub fn validate_session_call(
        env: Env,
        session_key: Address,
        target: Address,
        method: Symbol,
        amount: i128,
    ) -> bool {
        let allowed = Self::check_session_call(&env, &session_key, &target, &method, amount);
        if !allowed {
            event_schema::publish(
                &env,
                Symbol::new(&env, "session_keys"),
                Symbol::new(&env, "validate_failure"),
                &session_key,
                (target, method, amount),
            );
        }
        allowed
    }

    /// Check a session call against its record, updating cumulative spend.
    fn check_session_call(
        env: &Env,
        session_key: &Address,
        target: &Address,
        method: &Symbol,
        amount: i128,
    ) -> bool {
        let owner = match env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::OwnerIndex(session_key.clone()))
        {
            Some(o) => o,
            None => return false,
        };

        let key = DataKey::Session(owner, session_key.clone());
        let mut record: SessionKey = match env.storage().persistent().get(&key) {
            Some(r) => r,
            None => return false,
        };

        // Reject expired keys.
        let now = env.ledger().timestamp();
        if now > record.valid_until {
            return false;
        }

        // Reject unlisted targets.
        if !record.allowed_contracts.contains(target) {
            return false;
        }

        // Reject unlisted methods.
        if !record.allowed_methods.contains(method) {
            return false;
        }

        // Reject amounts exceeding cumulative quota.
        let new_spent = record.cumulative_spent.saturating_add(amount);
        if new_spent > record.max_cumulative_amount {
            return false;
        }

        // Update cumulative spend on success.
        record.cumulative_spent = new_spent;
        env.storage().persistent().set(&key, &record);

        true
    }
}

#[cfg(test)]
mod test;
