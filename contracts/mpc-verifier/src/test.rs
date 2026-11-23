use super::*;
use soroban_sdk::{testutils::Address as _, BytesN, Env};

fn setup() -> (Env, MpcVerifierClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let client = MpcVerifierClient::new(&env, &env.register(MpcVerifier, ()));
    let admin = Address::generate(&env);
    (env, client, admin)
}

fn register_two_cosigners(env: &Env, client: &MpcVerifierClient<'_>, admin: &Address) {
    client.register_cosigner(admin, &BytesN::from_array(env, &[1u8; 32]));
    client.register_cosigner(admin, &BytesN::from_array(env, &[2u8; 32]));
}

#[test]
fn threshold_at_cosigner_count_is_allowed() {
    let (env, client, admin) = setup();
    client.initialize(&admin, &1u32, &0u32);
    register_two_cosigners(&env, &client, &admin);

    client.set_threshold(&admin, &2u32);

    assert_eq!(client.threshold(), 2u32);
    assert_eq!(client.cosigner_count(), 2u32);
}

#[test]
#[should_panic]
fn threshold_above_cosigner_count_is_rejected() {
    let (env, client, admin) = setup();
    client.initialize(&admin, &1u32, &0u32);
    client.register_cosigner(&admin, &BytesN::from_array(&env, &[1u8; 32]));

    client.set_threshold(&admin, &2u32);
}

#[test]
#[should_panic]
fn zero_threshold_is_rejected() {
    let (_env, client, admin) = setup();
    client.initialize(&admin, &1u32, &0u32);

    client.set_threshold(&admin, &0u32);
}
