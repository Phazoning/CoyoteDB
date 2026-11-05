pub const TPM_NO_SESSIONS_HEADER: u16 = 0x8001;
pub const TPM_SESSIONS_HEADER: u16 = 0x8002;

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_CFB: u16 = 0x0043;

pub const TPM_CC_CREATE_PRIMARY: u32 = 0x00000131;
pub const TPM_CC_GETRANDOMNUMBER: u32 = 0x0000017B;
pub const TPM_CC_CREATE: u32 = 0x00000153;
pub const TPM_CC_LOAD: u32 = 0x00000157;
pub const TPM_CC_UNSEAL: u32 = 0x0000015E;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x00000165;

pub const TPM_RC_VER1: u16 = 0x100;
pub const TPM_RC_FMT1: u16 = 0x080;

pub const TPM_RH_OWNER: u32 = 0x40000001;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;

pub const TPM_RS_PW: u32 = 0x40000009;

pub const TPMA_OBJECT_FIXED_TPM: u32 = 0x00000002;
pub const TPMA_OBJECT_ST_CLEAR: u32 = 0x00000004;
pub const TPMA_OBJECT_FIXED_PARENT: u32 = 0x00000010;
pub const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 0x00000020;
pub const TPMA_OBJECT_USER_WITH_AUTH: u32 = 0x00000040;
pub const TPMA_OBJECT_ADMIN_WITH_POLICY: u32 = 0x00000080;
pub const TPMA_OBJECT_NO_DA: u32 = 0x00000400;
pub const TPMA_OBJECT_ENCRYPTED_DUPLICATION: u32 = 0x00000800;
pub const TPMA_OBJECT_RESTRICTED: u32 = 0x00010000;
pub const TPMA_OBJECT_DECRYPT: u32 = 0x00020000;
pub const TPMA_OBJECT_SIGN_ENCRYPT: u32 = 0x00040000;
pub const TPMA_OBJECT_X509_SIGN: u32 = 0x00080000;

pub const TPM_OBJECT_PRIMARY_STORAGE: u32 = TPMA_OBJECT_FIXED_TPM
    | TPMA_OBJECT_FIXED_PARENT
    | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
    | TPMA_OBJECT_USER_WITH_AUTH
    | TPMA_OBJECT_RESTRICTED
    | TPMA_OBJECT_DECRYPT;

pub const TPM_OBJECT_SEALED_DATA: u32 = TPMA_OBJECT_FIXED_TPM
    | TPMA_OBJECT_FIXED_PARENT
    | TPMA_OBJECT_USER_WITH_AUTH
    | TPMA_OBJECT_NO_DA;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum ReturnCode {
    Success,
    BadTag,
    Initialize,
    Failure,
    Sequence,
    Private,
    HMAC,
    Disabled,
    Exclusive,
    AuthType,
    AuthMissing,
    Policy,
    PCR,
    PCRChanged,
    Upgrade,
    TooManyContexts,
    AuthUnavaliable,
    Reboot,
    Unbalanced,
    CommandSize,
    CommandCode,
    AuthSize,
    AuthContext,
    NVRange,
    NVSize,
    NVLocked,
    NVAuthorization,
    NVUninitialized,
    NVSpace,
    NVDefined,
    BadContext,
    CPHash,
    Parent,
    NeedsTest,
    NoResult,
    Sensitive,
    ReadOnly,
    Asymmetric,
    Attributes,
    Hash,
    Value,
    Hierarchy,
    KeySize,
    MGF,
    Mode,
    Type,
    Handle,
    KDF,
    Range,
    AuthFail,
    Nonce,
    PP,
    Scheme,
    Size,
    Symmetric,
    Tag,
    Selector,
    Insufficient,
    Signature,
    Key,
    PolicyFail,
    Integrity,
    Ticket,
    ReservedBits,
    BadAuth,
    Expired,
    PolicyCC,
    Binding,
    Curve,
    EccPoint,
    FWLimited,
    SVNLimited,
    Channel,
    ChannelKey,
    RCNotRecognized, //out of spec, created for code coherence purposes
}
