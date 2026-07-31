mod tpm;
mod buffer;
mod errors;
mod aux_types;

fn main() {
    let tpm_device = tpm::TPM.new();

    let num = tpm_device.generate_random_number();

    match num {
        Ok(rand_num) => {
            println!(rand_num.get_self_buffer())
        }
        Err(error) => {
            println!("Error:");
            println!(error.err_content)
        }
    }
}
