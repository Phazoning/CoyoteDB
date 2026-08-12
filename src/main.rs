mod tpm;
mod buffer;
mod errors;

fn main() {
    println!("Loading device");
    let tpm_device = tpm::TPM::new();
    let mut tpm_loaded: tpm::TPM;
    match tpm_device{
        Ok(t) => {
            println!("Device loaded");
            tpm_loaded = t;
        }

        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return 
        }
    }

    println!("Passing random number command to TPM");
    let num = tpm_loaded.generate_random_number();

    match num {
        Ok(rand_num) => {
            println!("{}", rand_num.hex_string())
        }
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content)
        }
    }
}
