use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};

fn setup() -> (Env, SpendPolicyContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let client = SpendPolicyContractClient::new(&env, &env.register(SpendPolicyContract, ()));
    let master = Address::generate(&env);
    client.initialize(&master);
    (env, client, master)
}

#[test]
fn initial_limit_and_decrease_are_allowed() {
    let (env, client, _master) = setup();
    let asset = Address::generate(&env);
    let account = Address::generate(&env);

    client.set_limit(&asset, &account, &100i128);
    assert_eq!(client.get_limit(&asset, &account), 100);

    client.set_limit(&asset, &account, &40i128);
    assert_eq!(client.get_limit(&asset, &account), 40);
}

#[test]
fn immediate_limit_increase_is_rejected() {
    let (env, client, _master) = setup();
    let asset = Address::generate(&env);
    let account = Address::generate(&env);

    client.set_limit(&asset, &account, &100i128);

    assert_eq!(
        client.try_set_limit(&asset, &account, &101i128),
        Err(Ok(Error::LimitIncreaseRejected))
    );
    assert_eq!(client.get_limit(&asset, &account), 100);
}

#[test]
fn increase_through_schedule_limit_applies_after_delay() {
    let (env, client, _master) = setup();
    let asset = Address::generate(&env);
    let account = Address::generate(&env);
    env.ledger().set_timestamp(1_000);

    client.set_limit(&asset, &account, &100i128);
    client.schedule_limit(&asset, &account, &200i128);

    assert_eq!(
        client.try_apply_pending_limit(&asset, &account),
        Err(Ok(Error::TimelockNotExpired))
    );

    env.ledger().set_timestamp(1_000 + LIMIT_CHANGE_DELAY);
    assert_eq!(client.apply_pending_limit(&asset, &account), 200i128);
    assert_eq!(client.get_limit(&asset, &account), 200);
}
