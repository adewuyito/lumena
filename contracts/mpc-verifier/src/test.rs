use super::{DataKey, Error, MpcVerifier, MpcVerifierClient};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

#[test]
fn rejects_duplicate_registration() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(MpcVerifier, ());
    let client = MpcVerifierClient::new(&env, &id);
    let key = BytesN::from_array(&env, &[1; 32]);
    client.initialize(&admin, &1, &1);

    assert_eq!(client.register_cosigner(&admin, &key), 1);
    assert_eq!(
        client.try_register_cosigner(&admin, &key),
        Err(Ok(Error::DuplicateCosigner))
    );
    assert_eq!(client.cosigner_count(), 1);
}

#[test]
fn removal_compacts_indexes_and_preserves_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let outsider = Address::generate(&env);
    let id = env.register(MpcVerifier, ());
    let client = MpcVerifierClient::new(&env, &id);
    let removed = BytesN::from_array(&env, &[1; 32]);
    let remaining = BytesN::from_array(&env, &[2; 32]);
    client.initialize(&admin, &1, &1);
    client.register_cosigner(&admin, &removed);
    client.register_cosigner(&admin, &remaining);

    assert_eq!(
        client.try_remove_cosigner(&outsider, &0),
        Err(Ok(Error::Unauthorized))
    );
    client.remove_cosigner(&admin, &0);
    assert_eq!(client.cosigner_count(), 1);
    env.as_contract(&id, || {
        let storage = env.storage().persistent();
        assert_eq!(storage.get(&DataKey::Cosigner(0)), Some(remaining.clone()));
        assert!(!storage.has(&DataKey::Cosigner(1)));
    });
    assert_eq!(
        client.try_remove_cosigner(&admin, &1),
        Err(Ok(Error::UnknownCosigner))
    );
    assert_eq!(
        client.try_remove_cosigner(&admin, &0),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(client.cosigner_count(), 1);
    assert_eq!(
        client.try_register_cosigner(&admin, &remaining),
        Err(Ok(Error::DuplicateCosigner))
    );
    assert_eq!(client.register_cosigner(&admin, &removed), 2);
}
