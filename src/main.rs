mod tpm;
mod buffer;
mod errors;
mod aux_types;

fn main() {
    let tpm_device = tpm::TPM::new();
    let mut tpm_loaded: tpm::TPM;
    match tpm_device{
        Ok(t) => {
            tpm_loaded = t;
        }

        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content);
            return 
        }
    }

    let num = tpm_loaded.generate_random_number();

    match num {
        Ok(rand_num) => {
            println!("{:?}", rand_num.get_self_buffer())
        }
        Err(error) => {
            println!("Error:");
            println!("{}", error.err_content)
        }
    }
}
