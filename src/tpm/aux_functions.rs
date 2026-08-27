use super::definitions::{TPM_RC_FMT1, TPM_RC_VER1, ReturnCode};

pub fn parse_return_code(code_bytes: Vec<u8>) -> ReturnCode {
    let return_bin = u32::from_be_bytes(code_bytes.as_slice().try_into().unwrap());
    
    let format = (&return_bin >> 7) & 1 == 1;
    let is_special = (&return_bin >> 8) & 0 == 1;

    let mut rc_hex: u16;
    let code_format: u16;

    rc_hex = (return_bin & 0x3f) as u16;
    if !format {
        code_format = TPM_RC_VER1;
    } else {
        code_format = TPM_RC_FMT1;
    }

    let ret: ReturnCode;

    if code_format == TPM_RC_VER1{

        if is_special {
            match rc_hex {
                0x000 => {
                    ret = ReturnCode::Success
            }
                0x01e => {
                    ret = ReturnCode::BadTag
                }
                _ => {
                    ret = ReturnCode::RCNotRecognized
                }
            }
        }

        else {
            rc_hex += TPM_RC_VER1;
            ret = rc_match_format_zero(rc_hex);
        }
    } else {
        rc_hex += TPM_RC_FMT1;
        ret = rc_match_format_one(rc_hex);
    }
    return ret
}

fn rc_match_format_zero(code_hex: u16) -> ReturnCode {

    let ret: ReturnCode;

    match code_hex {
        0x100 => {
            ret = ReturnCode::Initialize   
        }

        0x101 => {
            ret = ReturnCode::Failure
        }

        0x103 => {
            ret = ReturnCode::Sequence
        }

        0x120 => {
            ret = ReturnCode::Disabled
        }

        0x121 => {
            ret = ReturnCode::Exclusive
        }

        0x124 => {
            ret = ReturnCode::AuthType
        }

        0x125 => {
            ret = ReturnCode::AuthMissing
        }

        0x126 => {
            ret = ReturnCode::Policy
        }

        0x127 => {
            ret = ReturnCode::PCR
        }

        0x128 => {
            ret = ReturnCode::PCRChanged
        }

        0x12d => {
            ret = ReturnCode::Upgrade
        }

        0x12e => {
            ret = ReturnCode::TooManyContexts
        }

        0x12f => {
            ret = ReturnCode::AuthUnavaliable
        }

        0x130 => {
            ret = ReturnCode::Reboot
        }

        0x131 => {
            ret = ReturnCode::Unbalanced
        }

        0x142 => {
            ret = ReturnCode::CommandSize
        }
        0x143 => {
            ret = ReturnCode::CommandCode
        }
        0x144 => {
            ret = ReturnCode::AuthSize
        }
        0x145 => {
            ret = ReturnCode::AuthContext
        }
        0x146 => {
            ret = ReturnCode::NVRange
        }
        0x147 => {
            ret = ReturnCode::NVSize
        }
        0x148 => {
            ret = ReturnCode::NVLocked
        }
        0x149 => {
            ret = ReturnCode::NVAuthorization
        }
        0x14a => {
            ret = ReturnCode::NVUninitialized
        }
        0x14b => {
            ret = ReturnCode::NVSpace
        }
        0x14c => {
            ret = ReturnCode::NVDefined
        }
        0x150 => {
            ret = ReturnCode::BadContext
        }
        0x151 => {
            ret = ReturnCode::CPHash
        }
        0x152 => {
            ret = ReturnCode::Parent
        }
        0x153 => {
            ret = ReturnCode::NeedsTest
        }
        0x154 => {
            ret = ReturnCode::NoResult
        }
        0x155 => {
            ret = ReturnCode::Sensitive
        }
        0x156 => {
            ret = ReturnCode::ReadOnly
        }

        _ => {
            ret = ReturnCode::RCNotRecognized
        }
    }

    return ret;
}


fn rc_match_format_one(code_hex: u16) -> ReturnCode {

    let ret: ReturnCode;

    match code_hex {
        0x081 => {
            ret = ReturnCode::Asymmetric
        }
        0x082 => {
            ret = ReturnCode::Attributes
        }
        0x083 => {
            ret = ReturnCode::Hash
        }
        0x084 => {
            ret = ReturnCode::Value
        }
        0x085 => {
            ret = ReturnCode::Hierarchy
        }
        0x087 => {
            ret = ReturnCode::KeySize
        }
        0x088 => {
            ret = ReturnCode::MGF
        }
        0x089 => {
            ret = ReturnCode::Mode
        }
        0x08a => {
            ret = ReturnCode::Type
        }
        0x08b => {
            ret = ReturnCode::Handle
        }
        0x08c => {
            ret = ReturnCode::KDF
        }
        0x08d => {
            ret = ReturnCode::Range
        }
        0x08e => {
            ret = ReturnCode::AuthFail
        }
        0x08f => {
            ret = ReturnCode::Nonce
        }
        0x090 => {
            ret = ReturnCode::PP
        }
        0x092 => {
            ret = ReturnCode::Scheme
        }
        0x095 => {
            ret = ReturnCode::Size
        }
        0x096 => {
            ret = ReturnCode::Symmetric
        }
        0x097 => {
            ret = ReturnCode::Tag
        }
        0x098 => {
            ret = ReturnCode::Selector
        }

        0x09a => {
            ret = ReturnCode::Insufficient
        }
        0x09b => {
            ret = ReturnCode::Signature
        }
        0x09c => {
            ret = ReturnCode::Key
        }
        0x09d => {
            ret = ReturnCode::PolicyFail
        }
        0x09f => {
            ret = ReturnCode::Integrity
        }
        0x0a0 => {
            ret = ReturnCode::Ticket
        }
        0x0a1 => {
            ret = ReturnCode::ReservedBits
        }
        0x0a2 => {
            ret = ReturnCode::BadAuth
        }
        0x0a3 => {
            ret = ReturnCode::Expired
        }
        0x0a4 => {
            ret = ReturnCode::PolicyCC
        }
        0x0a5 => {
            ret = ReturnCode::Binding
        }
        0x0a6 => {
            ret = ReturnCode::Curve
        }
        0x0a7 => {
            ret = ReturnCode::EccPoint
        }
        0x0a8 => {
            ret = ReturnCode::FWLimited
        }
        0x0a9 => {
            ret = ReturnCode::SVNLimited
        }
        0x0b0 => {
            ret = ReturnCode::Channel
        }
        0x0b1 => {
            ret = ReturnCode::ChannelKey
        }
        _ => {
            ret = ReturnCode::RCNotRecognized
        }
    }

    return ret
}

#[cfg(test)]
mod tests{
    use crate::tpm::definitions::ReturnCode;

use super::parse_return_code;

    //vec![0x00, 0x00, 0x00, 0x00];
    fn test_parse_rc_success(){
        let rc = vec![0x00, 0x00, 0x00, 0x00];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Success, parsed_rc)
    }

    //vec![0x00, 0x00, 0x00, 0x1e];
    fn test_parse_rc_bad_tag(){
        let rc = vec![0x00, 0x00, 0x00, 0x1e];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::BadTag, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x00];
    fn test_parse_rc_initialize(){
        let rc = vec![0x00, 0x00, 0x01, 0x00];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Initialize, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x01];    
    fn test_parse_rc_failure(){
        let rc = vec![0x00, 0x00, 0x01, 0x01];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Failure, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x03];
    fn test_parse_rc_sequence(){
        let rc = vec![0x00, 0x00, 0x01, 0x03];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Sequence, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x0b];
    fn test_parse_rc_private(){
        let rc = vec![0x00, 0x00, 0x01, 0x0b];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Private, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x19];
    fn test_parse_rc_hmac(){
        let rc = vec![0x00, 0x00, 0x01, 0x19];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::HMAC, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x20];
    fn test_parse_rc_disabled(){
        let rc = vec![0x00, 0x00, 0x01, 0x20];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Disabled, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x21];
    fn test_parse_rc_exclusive(){
        let rc = vec![0x00, 0x00, 0x01, 0x21];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Exclusive, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x24];
    fn test_parse_rc_auth_type(){
        let rc = vec![0x00, 0x00, 0x01, 0x24];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthType, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x25];
    fn test_parse_rc_auth_missing(){
        let rc = vec![0x00, 0x00, 0x01, 0x25];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthMissing, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x26];
    fn test_parse_rc_policy(){
        let rc = vec![0x00, 0x00, 0x01, 0x26];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Policy, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x27];
    fn test_parse_rc_pcr(){
        let rc = vec![0x00, 0x00, 0x01, 0x27];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::PCR, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x28];
    fn test_parse_rc_pcr_changed(){
        let rc = vec![0x00, 0x00, 0x01, 0x28];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::PCRChanged, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x2d];
    fn test_parse_rc_upgrade(){
        let rc = vec![0x00, 0x00, 0x01, 0x2d];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Upgrade, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x2e];
    fn test_parse_rc_too_many_contexts(){
        let rc = vec![0x00, 0x00, 0x01, 0x2e];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::TooManyContexts, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x2f];
    fn test_parse_rc_auth_unavaliable(){
        let rc = vec![0x00, 0x00, 0x01, 0x2f];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthUnavaliable, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x30];
    fn test_parse_rc_reboot(){
        let rc = vec![0x00, 0x00, 0x01, 0x30];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Reboot, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x31];
    fn test_parse_rc_unbalanced(){
        let rc = vec![0x00, 0x00, 0x01, 0x31];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Unbalanced, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x42];
    fn test_parse_rc_command_size(){
        let rc = vec![0x00, 0x00, 0x01, 0x42];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::CommandSize, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x43];
    fn test_parse_rc_command_code(){
        let rc = vec![0x00, 0x00, 0x01, 0x43];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::CommandCode, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x44];
    fn test_parse_rc_authsize(){
        let rc = vec![0x00, 0x00, 0x01, 0x44];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthSize, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x45];
    fn test_parse_rc_auth_context(){
        let rc = vec![0x00, 0x00, 0x01, 0x45];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthContext, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x46];
    fn test_parse_rc_nv_range(){
        let rc = vec![0x00, 0x00, 0x01, 0x46];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVRange, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x47];
    fn test_parse_rc_nv_size(){
        let rc = vec![0x00, 0x00, 0x01, 0x47];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVSize, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x48];
    fn test_parse_rc_nv_locked(){
        let rc = vec![0x00, 0x00, 0x01, 0x48];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVLocked, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x49];
    fn test_parse_rc_nv_authorization(){
        let rc = vec![0x00, 0x00, 0x01, 0x49];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVAuthorization, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x4a];
    fn test_parse_rc_nv_uninitialized(){
        let rc = vec![0x00, 0x00, 0x01, 0x4a];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVUninitialized, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x4b];
    fn test_parse_rc_nv_space(){
        let rc = vec![0x00, 0x00, 0x01, 0x4b];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVSpace, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x4c];
    fn test_parse_rc_nv_defined(){
        let rc = vec![0x00, 0x00, 0x01, 0x4c];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NVDefined, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5a];
    fn test_parse_rc_bad_context(){
        let rc = vec![0x00, 0x00, 0x01, 0x5a];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::BadContext, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5b];
    fn test_parse_rc_cphash(){
        let rc = vec![0x00, 0x00, 0x01, 0x5b];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::CPHash, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5c];
    fn test_parse_rc_parent(){
        let rc = vec![0x00, 0x00, 0x01, 0x5c];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Parent, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5d];
    fn test_parse_rc_needs_test(){
        let rc = vec![0x00, 0x00, 0x01, 0x5d];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NeedsTest, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5e];
    fn test_parse_rc_no_result(){
        let rc = vec![0x00, 0x00, 0x01, 0x5e];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::NoResult, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x5f];
    fn test_parse_rc_sensitive(){
        let rc = vec![0x00, 0x00, 0x01, 0x5f];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Sensitive, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x60];
    fn test_parse_rc_read_only(){
        let rc = vec![0x00, 0x00, 0x01, 0x60];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::ReadOnly, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x81];
    fn test_parse_rc_asymmetric(){
        let rc = vec![0x00, 0x00, 0x01, 0x81];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Asymmetric, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x82];
    fn test_parse_rc_attributes(){
        let rc = vec![0x00, 0x00, 0x01, 0x82];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Attributes, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x83];
    fn test_parse_rc_hash(){
        let rc = vec![0x00, 0x00, 0x01, 0x83];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Hash, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x84];
    fn test_parse_rc_value(){
        let rc = vec![0x00, 0x00, 0x01, 0x84];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Value, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x85];
    fn test_parse_rc_hierarchy(){
        let rc = vec![0x00, 0x00, 0x01, 0x85];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Hierarchy, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x86];
    fn test_parse_rc_key_size(){
        let rc = vec![0x00, 0x00, 0x01, 0x87];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::KeySize, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x87];
    fn test_parse_rc_mgf(){
        let rc = vec![0x00, 0x00, 0x01, 0x88];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::MGF, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0x88];
    fn test_parse_rc_mode(){
        let rc = vec![0x00, 0x00, 0x01, 0x89];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Mode, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x89];
    fn test_parse_rc_type(){
        let rc = vec![0x00, 0x00, 0x01, 0x8a];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Type, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8a];
    fn test_parse_rc_handle(){
        let rc = vec![0x00, 0x00, 0x01, 0x8b];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Handle, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8b];
    fn test_parse_rc_kdf(){
        let rc = vec![0x00, 0x00, 0x01, 0x8c];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::KDF, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8c];
    fn test_parse_rc_range(){
        let rc = vec![0x00, 0x00, 0x01, 0x8d];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Range, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8d];
    fn test_parse_rc_auth_fail(){
        let rc = vec![0x00, 0x00, 0x01, 0x8e];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::AuthFail, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8e];
    fn test_parse_rc_nonce(){
        let rc = vec![0x00, 0x00, 0x01, 0x8f];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Nonce, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x8f];
    fn test_parse_rc_pp(){
        let rc = vec![0x00, 0x00, 0x01, 0x90];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::PP, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x90];
    fn test_parse_rc_scheme(){
        let rc = vec![0x00, 0x00, 0x01, 0x92];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Scheme, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x92];
    fn test_parse_rc_size(){
        let rc = vec![0x00, 0x00, 0x01, 0x95];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Size, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x95];
    fn test_parse_rc_symmetric(){
        let rc = vec![0x00, 0x00, 0x01, 0x96];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Symmetric, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x96];
    fn test_parse_rc_tag(){
        let rc = vec![0x00, 0x00, 0x01, 0x97];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Tag, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x97];
    fn test_parse_rc_selector(){
        let rc = vec![0x00, 0x00, 0x01, 0x98];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Selector, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x98];
    fn test_parse_rc_insufficient(){
        let rc = vec![0x00, 0x00, 0x01, 0x9a];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Insufficient, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x9a];
    fn test_parse_rc_signature(){
        let rc = vec![0x00, 0x00, 0x01, 0x9b];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Signature, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x9b];
    fn test_parse_rc_key(){
        let rc = vec![0x00, 0x00, 0x01, 0x9c];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Key, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x9c];
    fn test_parse_rc_policy_fail(){
        let rc = vec![0x00, 0x00, 0x01, 0x9d];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::PolicyFail, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x9d];
    fn test_parse_rc_integrity(){
        let rc = vec![0x00, 0x00, 0x01, 0x9f];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Integrity, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0x9f];
    fn test_parse_rc_ticket(){
        let rc = vec![0x00, 0x00, 0x01, 0xa0];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Ticket, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0xa0];
    fn test_parse_rc_reserverd_bits(){
        let rc = vec![0x00, 0x00, 0x01, 0xa1];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::ReservedBits, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa1];
    fn test_parse_rc_bad_auth(){
        let rc = vec![0x00, 0x00, 0x01, 0xa2];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::BadAuth, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa2];
    fn test_parse_rc_expired(){
        let rc = vec![0x00, 0x00, 0x01, 0xa3];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Expired, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa3];
    fn test_parse_rc_policy_cc(){
        let rc = vec![0x00, 0x00, 0x01, 0xa4];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::PolicyCC, parsed_rc)
    }

    //vec![0x00, 0x00, 0x01, 0xa4];    
    fn test_parse_rc_binding(){
        let rc = vec![0x00, 0x00, 0x01, 0xa5];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Binding, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa5];
    fn test_parse_rc_curve(){
        let rc = vec![0x00, 0x00, 0x01, 0xa6];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Curve, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa6];
    fn test_parse_rc_ecc_point(){
        let rc = vec![0x00, 0x00, 0x01, 0xa7];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::EccPoint, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa7];
    fn test_parse_rc_fw_limited(){
        let rc = vec![0x00, 0x00, 0x01, 0xa8];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::FWLimited, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa8];
    fn test_parse_rc_svn_limited(){
        let rc = vec![0x00, 0x00, 0x01, 0xa9];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::SVNLimited, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xa9];
    fn test_parse_rc_channel(){
        let rc = vec![0x00, 0x00, 0x01, 0xb0];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::Channel, parsed_rc)
    }
    
    //vec![0x00, 0x00, 0x01, 0xb0];
    fn test_parse_rc_channel_key(){
        let rc = vec![0x00, 0x00, 0x01, 0xb1];

        let parsed_rc = parse_return_code(rc);

        assert_eq!(ReturnCode::ChannelKey, parsed_rc)
    }

}