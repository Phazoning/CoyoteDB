pub enum ErrorType {
    TpmCommandError,
    TpmAuthError,
    PlatformError,
    QuerySyntaxError,
    QueryExecutionError,
    WrittingError,
    ReadingError,
}

pub struct CustomError{
    pub err_type: ErrorType,
    pub err_content: String,
}
