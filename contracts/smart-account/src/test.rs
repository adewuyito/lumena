use super::*;
use event_schema::EventTopics;
use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Env, Symbol, TryFromVal,
};

#[test]
fn init_emits_standard_event_once() {
    let env = Env::default();
    let contract_id = env.register(SmartAccount, ());
    let client = SmartAccountClient::new(&env, &contract_id);

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let mut signers = Map::new(&env);
    signers.set(alice, 1u32);
    signers.set(bob, 2u32);

    client.init(&signers, &2u32);

    let events = env.events().all();
    assert_eq!(events.len(), 1);

    let (emitter, topics, data) = events.last().unwrap();
    assert_eq!(emitter, contract_id);
    assert_eq!(
        EventTopics::parse(&env, &topics),
        Some(EventTopics {
            contract: Symbol::new(&env, "smart_account"),
            action: Symbol::new(&env, "init"),
            wallet: contract_id.clone(),
        })
    );

    // Payload is [signer count, threshold].
    let payload: Vec<u32> = Vec::try_from_val(&env, &data).unwrap();
    assert_eq!(payload.get(0), Some(2u32));
    assert_eq!(payload.get(1), Some(2u32));
}
