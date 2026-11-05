use CoyoteDB::tpm::TPM;

fn integration_tpm() -> TPM {
    match TPM::new() {
        Ok(tpm) => tpm,
        Err(error) => panic!(
            "TPM integration test requires a usable TPM: {}",
            error.err_content
        ),
    }
}

#[test]
fn generate_random_number_works_with_tpm() {
    let mut tpm = integration_tpm();

    let random = match tpm.generate_random_number() {
        Ok(random) => random,
        Err(error) => panic!("TPM random command should succeed: {}", error.err_content),
    };

    assert!(!random.get_self_buffer().is_empty());
}

#[test]
fn create_primary_works_with_tpm() {
    let mut tpm = integration_tpm();

    let response = match tpm.create_primary() {
        Ok(response) => response,
        Err(error) => panic!(
            "TPM CreatePrimary command should succeed: {}",
            error.err_content
        ),
    };

    assert_ne!(response.get_object_handle(), 0);
    assert!(!response.get_out_public().is_empty());
    assert!(!response.get_creation_data().is_empty());
    assert!(!response.get_creation_hash().is_empty());
    assert!(!response.get_creation_ticket().is_empty());
}

#[test]
fn seal_load_and_unseal_works_with_tpm() {
    let mut tpm = integration_tpm();
    let secret = b"CoyoteDB TPM integration secret";

    let primary = match tpm.create_primary() {
        Ok(response) => response,
        Err(error) => panic!(
            "TPM CreatePrimary command should succeed: {}",
            error.err_content
        ),
    };
    let sealed = match tpm.create_sealed(primary.get_object_handle(), secret) {
        Ok(response) => response,
        Err(error) => panic!("TPM Create command should succeed: {}", error.err_content),
    };
    let loaded = match tpm.load_sealed(
        primary.get_object_handle(),
        &sealed.get_private(),
        &sealed.get_public(),
    ) {
        Ok(response) => response,
        Err(error) => panic!("TPM Load command should succeed: {}", error.err_content),
    };

    let unsealed = match tpm.unseal(loaded.get_object_handle()) {
        Ok(data) => data,
        Err(error) => panic!("TPM Unseal command should succeed: {}", error.err_content),
    };

    assert_eq!(unsealed, secret);
    if let Err(error) = tpm.flush_context(loaded.get_object_handle()) {
        panic!(
            "TPM FlushContext for sealed object should succeed: {}",
            error.err_content
        );
    }
    if let Err(error) = tpm.flush_context(primary.get_object_handle()) {
        panic!(
            "TPM FlushContext for primary object should succeed: {}",
            error.err_content
        );
    }
}
