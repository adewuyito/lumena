use super::*;
use event_schema::EventTopics;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    Env, Symbol, Vec,
};

fn setup() -> (Env, SessionKeysContractClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register(SessionKeysContract, ());
    let client = SessionKeysContractClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    (env, client, owner, contract_id)
}

fn allowed(env: &Env, target: &Address) -> (Vec<Address>, Vec<Symbol>) {
    let mut contracts = Vec::new(env);
    contracts.push_back(target.clone());
    let mut methods = Vec::new(env);
    methods.push_back(Symbol::new(env, "transfer"));
    (contracts, methods)
}

fn last_event(env: &Env) -> (Address, EventTopics) {
    let (emitter, topics, _) = env.events().all().last().unwrap();
    (emitter, EventTopics::parse(env, &topics).unwrap())
}

#[test]
fn register_emits_event() {
    let (env, client, owner, contract_id) = setup();
    let session_key = Address::generate(&env);
    let target = Address::generate(&env);
    let (contracts, methods) = allowed(&env, &target);

    client.initialize(&3_600u64);
    client.register_session_key(
        &owner,
        &session_key,
        &2_000u64,
        &contracts,
        &methods,
        &1_000i128,
    );

    let (emitter, topics) = last_event(&env);
    assert_eq!(emitter, contract_id);
    assert_eq!(topics.contract, Symbol::new(&env, "session_keys"));
    assert_eq!(topics.action, Symbol::new(&env, "register"));
    assert_eq!(topics.wallet, owner);
}

#[test]
fn revoke_emits_event() {
    let (env, client, owner, contract_id) = setup();
    let session_key = Address::generate(&env);
    let target = Address::generate(&env);
    let (contracts, methods) = allowed(&env, &target);

    client.initialize(&3_600u64);
    client.register_session_key(
        &owner,
        &session_key,
        &2_000u64,
        &contracts,
        &methods,
        &1_000i128,
    );
    client.revoke_session_key(&owner, &session_key);

    let (emitter, topics) = last_event(&env);
    assert_eq!(emitter, contract_id);
    assert_eq!(topics.contract, Symbol::new(&env, "session_keys"));
    assert_eq!(topics.action, Symbol::new(&env, "revoke"));
    assert_eq!(topics.wallet, owner);
}

#[test]
#[should_panic]
fn over_long_expiry_is_rejected() {
    let (env, client, owner, _contract_id) = setup();
    let session_key = Address::generate(&env);
    let target = Address::generate(&env);
    let (contracts, methods) = allowed(&env, &target);

    client.initialize(&3_600u64);
    // now (1_000) + max_ttl (3_600) = 4_600.
    client.register_session_key(
        &owner,
        &session_key,
        &4_601u64,
        &contracts,
        &methods,
        &1_000i128,
    );
}

#[test]
fn validate_failure_emits_event() {
    let (env, client, owner, contract_id) = setup();
    let session_key = Address::generate(&env);
    let target = Address::generate(&env);
    let unlisted = Address::generate(&env);
    let method = Symbol::new(&env, "transfer");
    let (contracts, methods) = allowed(&env, &target);

    client.initialize(&3_600u64);
    client.register_session_key(
        &owner,
        &session_key,
        &2_000u64,
        &contracts,
        &methods,
        &1_000i128,
    );

    assert!(!client.validate_session_call(&session_key, &unlisted, &method, &100i128));

    let (emitter, topics) = last_event(&env);
    assert_eq!(emitter, contract_id);
    assert_eq!(topics.contract, Symbol::new(&env, "session_keys"));
    assert_eq!(topics.action, Symbol::new(&env, "validate_failure"));
    assert_eq!(topics.wallet, session_key);
}

#[test]
fn valid_call_does_not_emit_failure_event() {
    let (env, client, owner, _contract_id) = setup();
    let session_key = Address::generate(&env);
    let target = Address::generate(&env);
    let method = Symbol::new(&env, "transfer");
    let (contracts, methods) = allowed(&env, &target);

    client.initialize(&3_600u64);
    client.register_session_key(
        &owner,
        &session_key,
        &2_000u64,
        &contracts,
        &methods,
        &1_000i128,
    );

    assert!(client.validate_session_call(&session_key, &target, &method, &100i128));

    let (_, topics) = last_event(&env);
    assert_eq!(topics.action, Symbol::new(&env, "register"));
}
