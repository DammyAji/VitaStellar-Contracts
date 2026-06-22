extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, String};

fn setup(env: &Env) -> (ZKPRegistryClient<'_>, Address) {
    let contract_id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(env, &contract_id);
    (client, contract_id)
}

fn make_proof(
    env: &Env,
    label: &'static [u8],
    proof_type: ZKPType,
    hash: ZKPHashFunction,
) -> ZKProof {
    ZKProof {
        proof_type,
        hash_function: hash,
        circuit_id: String::from_str(env, "circuit"),
        public_inputs: vec![env, Bytes::from_slice(env, label)],
        proof_data: Bytes::from_slice(env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: BytesN::from_array(env, &[1u8; 32]),
        verification_gas: 50_000,
        created_at: env.ledger().timestamp(),
    }
}

fn make_expiration_payload(env: &Env, valid_until: u64) -> Bytes {
    let mut out = Bytes::new(env);
    out.append(&Bytes::from_slice(env, &valid_until.to_be_bytes()));
    let mut commitment_payload = Bytes::new(env);
    commitment_payload.append(&Bytes::from_slice(env, b"zkp_registry:cred_exp"));
    commitment_payload.append(&Bytes::from_slice(env, &valid_until.to_be_bytes()));
    let commitment: BytesN<32> = env.crypto().sha256(&commitment_payload).into();
    out.append(&Bytes::from_slice(env, &commitment.to_array()));
    out
}

fn init_contract(env: &Env) -> (ZKPRegistryClient<'_>, Address) {
    let (client, contract_id) = setup(env);
    let admin = Address::generate(env);
    client.initialize(&admin);
    (client, contract_id)
}

#[test]
fn test_initialize_and_register_circuit() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let (client, _id) = setup(&env);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let circuit_id = String::from_str(&env, "circuit-a");
    let vk_hash = BytesN::from_array(&env, &[2u8; 32]);
    let pk_hash = BytesN::from_array(&env, &[3u8; 32]);
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &2u32,
        &3u32,
        &100u32,
        &128u32,
        &vk_hash,
        &pk_hash,
        &true,
    );

    let params = client.get_circuit_params(&circuit_id);
    assert_eq!(params.circuit_id, circuit_id);
    assert_eq!(params.circuit_type, ZKPType::SNARK);
    assert_eq!(params.num_public_inputs, 2);
}

#[test]
fn test_submit_zkp_smoke() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let (client, _) = setup(&env);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let circuit_id = String::from_str(&env, "circuit-b");
    let vk_hash = BytesN::from_array(&env, &[4u8; 32]);
    let pk_hash = BytesN::from_array(&env, &[5u8; 32]);
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &1u32,
        &1u32,
        &50u32,
        &128u32,
        &vk_hash,
        &pk_hash,
        &false,
    );

    let submitter = Address::generate(&env);
    let proof_id = BytesN::from_array(&env, &[6u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"input")];
    let proof = Bytes::from_slice(&env, b"0123456789abcdef0123456789abcdef");

    client.submit_zkp(
        &submitter,
        &proof_id,
        &ZKPType::SNARK,
        &ZKPHashFunction::Poseidon,
        &circuit_id,
        &inputs,
        &proof,
        &vk_hash,
        &50_000u64,
    );

    let result = client.get_verification_result(&proof_id);
    assert!(result.is_valid);
    assert_eq!(result.verifier, submitter);
}

#[test]
fn test_create_credential_proof_valid_future_window() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "medical_license");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_100);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    let proof = client.get_credential_proof(&holder, &credential_type);
    assert_eq!(proof.issuer, issuer);
    assert!(proof.is_verified);
}

#[test]
fn test_create_credential_proof_about_to_expire() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "researcher");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_001);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_exact_boundary_is_valid() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "nurse");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_000);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_future_far_is_valid() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "surgeon");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 9_999_999);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_expired_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "pharmacist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 999_999);

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::CredentialExpired)));
}

#[test]
fn test_create_credential_proof_tampered_commitment_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "pathologist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let mut encrypted_expiration = make_expiration_payload(&env, 1_000_050);
    let mut tampered = [0u8; 40];
    encrypted_expiration.copy_into_slice(&mut tampered);
    tampered[39] ^= 0x01;
    encrypted_expiration = Bytes::from_slice(&env, &tampered);

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::CommitmentMismatch)));
}

#[test]
fn test_create_credential_proof_short_payload_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "therapist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = Bytes::from_slice(&env, b"short");

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::InvalidInput)));
}

// ==================== verify_range_proof_internal tests ====================

use super::range_proof::{make_range_proof_data, range_commitment, MIN_PROOF_LEN};

fn make_range_proof_fixture(
    env: &Env,
    enc_value: &[u8],
    min: u64,
    max: u64,
    vk: [u8; 32],
) -> (Address, BytesN<32>, Bytes, BytesN<32>) {
    let prover = Address::generate(env);
    let proof_id = BytesN::from_array(env, &[0xddu8; 32]);
    let encrypted_value = Bytes::from_slice(env, enc_value);
    let vk_hash = BytesN::from_array(env, &vk);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: encrypted_value.clone(),
        min_value: min,
        max_value: max,
        proof_data: Bytes::new(env),
        vk_hash: vk_hash.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(env, &rp);
    (prover, vk_hash, encrypted_value, BytesN::from_array(env, &proof_id.to_array()))
}

fn init_rng(env: &Env) -> ZKPRegistryClient<'_> {
    let id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(env, &id);
    let admin = Address::generate(env);
    client.initialize(&admin);
    client
}

#[test]
fn test_range_proof_valid_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let client = init_rng(&env);

    let enc_value = Bytes::from_slice(&env, b"secret_amount");
    let vk = BytesN::from_array(&env, &[0x11u8; 32]);
    let min = 1u64;
    let max = 100u64;
    let rp = RangeProof {
        prover: Address::generate(&env),
        encrypted_value: enc_value.clone(),
        min_value: min,
        max_value: max,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(&env, &rp);
    let prover = Address::generate(&env);
    let proof_id = BytesN::from_array(&env, &[0x01u8; 32]);

    client.create_range_proof(&prover, &proof_id, &enc_value, &min, &max, &proof_data, &vk, &1_000);
    let stored = client.get_range_proof(&proof_id);
    assert_eq!(stored.min_value, min);
    assert_eq!(stored.max_value, max);
}

#[test]
fn test_range_proof_empty_proof_data_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x02u8; 32]),
        &enc, &1, &100, &Bytes::new(&env), &vk, &1_000,
    );
    assert!(r.is_err());
}

#[test]
fn test_range_proof_short_proof_data_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let short_data = Bytes::from_slice(&env, b"tooshort");
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x03u8; 32]),
        &enc, &1, &100, &short_data, &vk, &1_000,
    );
    assert!(r.is_err());
}

#[test]
fn test_range_proof_wrong_version_returns_version_mismatch() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 1,
        max_value: 100,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let mut pd_bytes = [0u8; 36];
    make_range_proof_data(&env, &rp).copy_into_slice(&mut pd_bytes);
    // Corrupt the version tag
    pd_bytes[0] = 0xff;
    let bad_pd = Bytes::from_slice(&env, &pd_bytes);
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x04u8; 32]),
        &enc, &1, &100, &bad_pd, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::VersionMismatch)));
}

#[test]
fn test_range_proof_tampered_commitment_returns_invalid_range_proof() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"secret");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 10,
        max_value: 200,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let mut pd_bytes = [0u8; 36];
    make_range_proof_data(&env, &rp).copy_into_slice(&mut pd_bytes);
    pd_bytes[35] ^= 0x01;
    let bad_pd = Bytes::from_slice(&env, &pd_bytes);
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x05u8; 32]),
        &enc, &10, &200, &bad_pd, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRangeProof)));
}

#[test]
fn test_range_proof_wrong_vk_hash_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"secret");
    let correct_vk = BytesN::from_array(&env, &[0xaau8; 32]);
    let wrong_vk = BytesN::from_array(&env, &[0xbbu8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 1,
        max_value: 50,
        proof_data: Bytes::new(&env),
        vk_hash: correct_vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(&env, &rp); // uses correct_vk
    // Submit with wrong_vk → commitment mismatch
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x06u8; 32]),
        &enc, &1, &50, &proof_data, &wrong_vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRangeProof)));
}

#[test]
fn test_range_proof_wrong_min_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 1,
        max_value: 100,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(&env, &rp);
    // Submit with different min_value
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x07u8; 32]),
        &enc, &5, &100, &proof_data, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRangeProof)));
}

#[test]
fn test_range_proof_wrong_max_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 1,
        max_value: 100,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(&env, &rp);
    // Submit with different max_value → commitment mismatch
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x08u8; 32]),
        &enc, &1, &1_000_000, &proof_data, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRangeProof)));
}

#[test]
fn test_range_proof_wrong_encrypted_value_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"original_value");
    let forged_enc = Bytes::from_slice(&env, b"forged_value");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let rp = RangeProof {
        prover: prover.clone(),
        encrypted_value: enc.clone(),
        min_value: 1,
        max_value: 100,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let proof_data = make_range_proof_data(&env, &rp); // matches enc
    // Submit with different encrypted_value
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x09u8; 32]),
        &forged_enc, &1, &100, &proof_data, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRangeProof)));
}

#[test]
fn test_range_proof_min_equals_max_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let prover = Address::generate(&env);
    let enc = Bytes::from_slice(&env, b"v");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let pd = Bytes::from_slice(&env, &[0u8; 36]);
    let r = client.try_create_range_proof(
        &prover, &BytesN::from_array(&env, &[0x0au8; 32]),
        &enc, &50, &50, &pd, &vk, &1_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidRange)));
}

// Property tests

#[test]
fn test_range_proof_prop_any_byte_flip_in_commitment_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let client = init_rng(&env);
    let enc = Bytes::from_slice(&env, b"prop_val");
    let vk = BytesN::from_array(&env, &[0x55u8; 32]);
    let rp = RangeProof {
        prover: Address::generate(&env),
        encrypted_value: enc.clone(),
        min_value: 0,
        max_value: u64::MAX,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let mut pd_bytes = [0u8; 36];
    make_range_proof_data(&env, &rp).copy_into_slice(&mut pd_bytes);

    for i in 4..36usize {
        let mut tampered = pd_bytes;
        tampered[i] ^= 0x80;
        let prover = Address::generate(&env);
        let pid = BytesN::from_array(&env, &[i as u8; 32]);
        let r = client.try_create_range_proof(
            &prover, &pid,
            &enc, &0, &u64::MAX,
            &Bytes::from_slice(&env, &tampered), &vk, &1_000,
        );
        assert_eq!(r, Err(Ok(Error::InvalidRangeProof)), "flip at byte {i} should fail");
    }
}

#[test]
fn test_range_proof_prop_different_bounds_different_commitments() {
    let env = Env::default();
    let enc = Bytes::from_slice(&env, b"enc");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let mk = |min: u64, max: u64| {
        let rp = RangeProof {
            prover: Address::generate(&env),
            encrypted_value: enc.clone(),
            min_value: min,
            max_value: max,
            proof_data: Bytes::new(&env),
            vk_hash: vk.clone(),
            verification_gas: 1_000,
            created_at: 0,
        };
        let comm = range_commitment(&env, &rp);
        comm.to_array()
    };
    assert_ne!(mk(0, 100), mk(0, 1_000_000));
    assert_ne!(mk(0, 100), mk(50, 100));
    assert_ne!(mk(1, 99), mk(0, 100));
}

#[test]
fn test_range_proof_prop_commitment_is_deterministic() {
    let env = Env::default();
    let enc = Bytes::from_slice(&env, b"det");
    let vk = BytesN::from_array(&env, &[2u8; 32]);
    let rp = RangeProof {
        prover: Address::generate(&env),
        encrypted_value: enc.clone(),
        min_value: 10,
        max_value: 20,
        proof_data: Bytes::new(&env),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let c1 = range_commitment(&env, &rp).to_array();
    let c2 = range_commitment(&env, &rp).to_array();
    assert_eq!(c1, c2);
}
