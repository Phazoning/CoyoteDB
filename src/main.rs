mod buffer;
mod errors;
mod tpm;

fn main() {
    println!("Loading device");
    let tpm_device = tpm::TPM::new();
    let mut tpm_loaded: tpm::TPM;
    match tpm_device {
        Ok(t) => {
            println!("Device loaded");
            tpm_loaded = t;
        }

        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return;
        }
    }

    let primary_response = match tpm_loaded.create_primary() {
        Ok(response) => response,
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return;
        }
    };


    let sealed_data = b"AAAABBBBCCCCC";

    let sealed_response = match tpm_loaded.create_sealed(primary_response.get_object_handle(), sealed_data){
        Ok(res) => {
            res
        }
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return;
        }
    };

    let loaded_response = match tpm_loaded.load_sealed(primary_response.get_object_handle(), 
        &sealed_response.get_private(), 
        &sealed_response.get_public()
    ){
        Ok(res) => {
            res
        }
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return;
        }
    };

    let unsealed_response = match tpm_loaded.unseal(loaded_response.get_object_handle()){
        Ok(res) => {
            res
        }
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return;
        }
    };

    assert!(&unsealed_response == sealed_data);
}
