#[derive(Debug)]
pub enum ErrorType {
    TpmCommandError,
    TpmAuthError,
    PlatformError,
    QuerySyntaxError,
    QueryExecutionError,
    WrittingError,
    ReadingError,
    TPMError,
}

#[derive(Debug)]
pub struct CustomError {
    pub err_type: ErrorType,
    pub err_content: String,
}
