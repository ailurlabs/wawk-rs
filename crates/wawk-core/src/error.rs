use thiserror::Error;

/// Errors that can occur during AWK execution.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum AwkError {
    #[error("Lexer error at position {position}: {message}")]
    LexError { message: String, position: usize },

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Undefined variable: {0}")]
    UndefinedVariable(String),

    #[error("I/O error: {0}")]
    IoError(String),
}

pub type AwkResult<T> = Result<T, AwkError>;
