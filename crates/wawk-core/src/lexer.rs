//! Lexer for the AWK language using `nom` parser combinators.
//!
//! Tokenizes AWK source code into a stream of tokens for the parser.

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{char, satisfy},
    combinator::{opt, recognize, value},
    sequence::{pair, tuple},
    IResult,
};

use crate::error::{AwkError, AwkResult};

/// Token types produced by the lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    // Literals
    Number(f64),
    StringLiteral(String),
    Regex(String),

    // Identifiers and keywords
    Ident(String),
    Begin,
    End,
    If,
    Else,
    While,
    For,
    In,
    Delete,
    Print,
    Printf,
    Next,
    Break,
    Continue,
    Function,
    Return,
    Getline,
    Nextfile,
    True,
    False,
    Null,

    // Special variables
    NF,
    NR,
    FS,
    RS,
    OFS,
    ORS,
    FILENAME,
    ARGV,
    ARGC,

    // Operators
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Caret,
    Assign,
    PlusAssign,
    MinusAssign,
    StarAssign,
    SlashAssign,
    PercentAssign,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Not,
    Increment,
    Decrement,

    // Delimiters
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Semicolon,
    Comma,
    Dollar,
    Question,
    Colon,
    Dot,
    Pipe,
    PipeAmp, // |&
    Newline,

    // Redirection
    GtGt, // >>

    // Match operators
    Match,    // ~
    NotMatch, // !~

    // End of input
    Eof,
}

/// Lexer state holding the source and current position.
#[derive(Debug)]
pub struct Lexer {
    tokens: Vec<Token>,
    pub pos: usize,
}

impl Lexer {
    /// Maximum allowed input size in bytes (10 MB).
    const MAX_INPUT_SIZE: usize = 10_000_000;
    /// Tokenize the given AWK source code.
    pub fn tokenize(input: &str) -> AwkResult<Vec<Token>> {
        if input.len() > Self::MAX_INPUT_SIZE {
            return Err(AwkError::LexError {
                message: format!("Input size {} exceeds maximum allowed size of {} bytes", input.len(), Self::MAX_INPUT_SIZE),
                position: 0,
            });
        }
        // Pre-process: handle backslash-newline continuation
        let processed = preprocess_continuation(input);
        let mut tokens = Vec::new();
        let mut remaining = processed.as_str();

        while !remaining.is_empty() {
            // Skip whitespace (not newlines)
            remaining = skip_whitespace(remaining);
            if remaining.is_empty() {
                break;
            }

            // Skip line comments
            if remaining.starts_with('#') {
                if let Some(pos) = remaining.find('\n') {
                    remaining = &remaining[pos..];
                    continue;
                } else {
                    break;
                }
            }

            // Try to parse a token
            match parse_token(remaining) {
                Ok((rest, token)) => {
                    tokens.push(token);
                    remaining = rest;
                }
                Err(_) => {
                    return Err(AwkError::LexError {
                        message: format!("Unexpected character: {:?}", remaining.chars().next().unwrap_or('?')),
                        position: processed.len() - remaining.len(),
                    });
                }
            }
        }

        tokens.push(Token::Eof);
        Ok(tokens)
    }

    /// Create a new lexer from tokens.
    #[must_use]
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    /// Peek at the current token without consuming it.
    #[must_use]
    pub fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    /// Peek at a token at an offset from the current position.
    #[must_use]
    pub fn peek_at(&self, offset: usize) -> &Token {
        self.tokens.get(self.pos + offset).unwrap_or(&Token::Eof)
    }

    /// Consume and return the current token.
    pub fn advance(&mut self) -> Token {
        let token = self.tokens.get(self.pos).cloned().unwrap_or(Token::Eof);
        self.pos += 1;
        token
    }

    /// Check if we're at the end of input.
    #[must_use]
    pub fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len() || matches!(self.peek(), Token::Eof)
    }

    /// Expect and consume a specific token.
    pub fn expect(&mut self, expected: &Token) -> AwkResult<()> {
        let token = self.advance();
        if &token == expected {
            Ok(())
        } else {
            Err(AwkError::ParseError(format!(
                "Expected {:?}, got {:?}",
                expected, token
            )))
        }
    }

    /// Skip newline tokens.
    pub fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline) {
            self.advance();
        }
    }
}

/// Pre-process AWK source to handle backslash-newline continuation.
/// In AWK, a backslash immediately followed by a newline joins the next line.
fn preprocess_continuation(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if chars.peek() == Some(&'\n') {
                chars.next(); // consume the newline - line continuation
                              // Optionally skip leading whitespace on next line
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    result
}

fn skip_whitespace(input: &str) -> &str {
    input.trim_start_matches([' ', '\t', '\r'])
}

fn parse_token(input: &str) -> IResult<&str, Token> {
    alt((
        parse_newline,
        parse_regex,
        parse_number,
        parse_string,
        parse_keyword_or_ident,
        parse_operator,
        parse_delimiter,
    ))(input)
}

fn parse_newline(input: &str) -> IResult<&str, Token> {
    value(Token::Newline, char('\n'))(input)
}

fn parse_number(input: &str) -> IResult<&str, Token> {
    // Check for hex literal: 0x or 0X
    if input.starts_with("0x") || input.starts_with("0X") {
        let rest = &input[2..];
        let hex_end = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        if hex_end == 0 {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::HexDigit,
            )));
        }
        let hex_str = &rest[..hex_end];
        let remaining = &rest[hex_end..];
        // Make sure not followed by identifier chars
        if remaining.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::HexDigit,
            )));
        }
        let n = u64::from_str_radix(hex_str, 16).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::HexDigit,
            ))
        })? as f64;
        return Ok((remaining, Token::Number(n)));
    }

    let (rest, num_str) = recognize(tuple((
        take_while1(|c: char| c.is_ascii_digit()),
        opt(pair(char('.'), take_while1(|c: char| c.is_ascii_digit()))),
        opt(tuple((
            satisfy(|c| c == 'e' || c == 'E'),
            opt(alt((char('+'), char('-')))),
            take_while1(|c: char| c.is_ascii_digit()),
        ))),
    )))(input)?;

    // Make sure this isn't followed by an identifier character
    if rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Float,
        )));
    }

    let n: f64 = num_str.parse().map_err(|_| {
        nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Float))
    })?;
    Ok((rest, Token::Number(n)))
}

fn parse_string(input: &str) -> IResult<&str, Token> {
    let (rest, _) = char('"')(input)?;
    let mut result = String::new();
    let mut chars = rest.chars();
    let mut consumed = 0;

    loop {
        match chars.next() {
            Some('"') => {
                consumed += 1;
                return Ok((&rest[consumed..], Token::StringLiteral(result)));
            }
            Some('\\') => {
                consumed += 1;
                match chars.next() {
                    Some('n') => {
                        result.push('\n');
                        consumed += 1;
                    }
                    Some('t') => {
                        result.push('\t');
                        consumed += 1;
                    }
                    Some('r') => {
                        result.push('\r');
                        consumed += 1;
                    }
                    Some('\\') => {
                        result.push('\\');
                        consumed += 1;
                    }
                    Some('"') => {
                        result.push('"');
                        consumed += 1;
                    }
                    Some('a') => {
                        result.push('\x07'); // alert/bell
                        consumed += 1;
                    }
                    Some('b') => {
                        result.push('\x08'); // backspace
                        consumed += 1;
                    }
                    Some('f') => {
                        result.push('\x0C'); // form feed
                        consumed += 1;
                    }
                    Some('v') => {
                        result.push('\x0B'); // vertical tab
                        consumed += 1;
                    }
                    Some('/') => {
                        result.push('/');
                        consumed += 1;
                    }
                    Some('x') => {
                        // Hex escape: \xNN (1-2 hex digits)
                        consumed += 1;
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(&next_ch) = chars.clone().peekable().peek() {
                                if next_ch.is_ascii_hexdigit() {
                                    if let Some(c) = chars.next() {
                                        hex.push(c);
                                    }
                                    consumed += 1;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    }
                    Some(c) if c.is_ascii_digit() && c != '8' && c != '9' => {
                        // Octal escape: \OOO (1-3 octal digits)
                        let mut oct = String::new();
                        oct.push(c);
                        consumed += 1;
                        for _ in 0..2 {
                            if let Some(&next_ch) = chars.clone().peekable().peek() {
                                if ('0'..='7').contains(&next_ch) {
                                    if let Some(c) = chars.next() {
                                        oct.push(c);
                                    }
                                    consumed += 1;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&oct, 8) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push_str(&oct);
                        }
                    }
                    Some(c) => {
                        result.push('\\');
                        result.push(c);
                        consumed += c.len_utf8();
                    }
                    None => {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                }
            }
            Some(c) => {
                result.push(c);
                consumed += c.len_utf8();
            }
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Eof,
                )));
            }
        }
    }
}

fn parse_regex(input: &str) -> IResult<&str, Token> {
    // Regex starts with / but not // (which would be division)
    let (rest, _) = char('/')(input)?;

    // Allow empty regex // (matches every line, like gawk)
    if let Some(stripped) = rest.strip_prefix('/') {
        return Ok((stripped, Token::Regex(String::new())));
    }

    let mut result = String::new();
    let mut chars = rest.chars();
    let mut consumed = 0;

    loop {
        match chars.next() {
            Some('/') => {
                consumed += 1;
                return Ok((&rest[consumed..], Token::Regex(result)));
            }
            Some('\\') => {
                consumed += 1;
                match chars.next() {
                    Some('/') => {
                        result.push('/');
                        consumed += 1;
                    }
                    Some(c) => {
                        result.push('\\');
                        result.push(c);
                        consumed += c.len_utf8();
                    }
                    None => {
                        return Err(nom::Err::Error(nom::error::Error::new(
                            input,
                            nom::error::ErrorKind::Eof,
                        )));
                    }
                }
            }
            Some(c) => {
                result.push(c);
                consumed += c.len_utf8();
            }
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Eof,
                )));
            }
        }
    }
}

fn parse_keyword_or_ident(input: &str) -> IResult<&str, Token> {
    let (rest, word) = recognize(pair(
        satisfy(|c| c.is_ascii_alphabetic() || c == '_'),
        take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
    ))(input)?;

    let token = match word {
        "BEGIN" => Token::Begin,
        "END" => Token::End,
        "if" => Token::If,
        "else" => Token::Else,
        "while" => Token::While,
        "for" => Token::For,
        "in" => Token::In,
        "delete" => Token::Delete,
        "print" => Token::Print,
        "printf" => Token::Printf,
        "next" => Token::Next,
        "break" => Token::Break,
        "continue" => Token::Continue,
        "function" => Token::Function,
        "return" => Token::Return,
        "getline" => Token::Getline,
        "nextfile" => Token::Nextfile,
        "true" => Token::True,
        "false" => Token::False,
        "null" => Token::Null,
        "NF" => Token::NF,
        "NR" => Token::NR,
        "FS" => Token::FS,
        "RS" => Token::RS,
        "OFS" => Token::OFS,
        "ORS" => Token::ORS,
        "FILENAME" => Token::FILENAME,
        "ARGV" => Token::ARGV,
        "ARGC" => Token::ARGC,
        _ => Token::Ident(word.to_string()),
    };

    Ok((rest, token))
}

fn parse_operator(input: &str) -> IResult<&str, Token> {
    alt((
        // Multi-char operators first (grouped)
        alt((
            value(Token::PlusAssign, tag("+=")),
            value(Token::MinusAssign, tag("-=")),
            value(Token::StarAssign, tag("*=")),
            value(Token::SlashAssign, tag("/=")),
            value(Token::PercentAssign, tag("%=")),
            value(Token::Increment, tag("++")),
            value(Token::Decrement, tag("--")),
            value(Token::Eq, tag("==")),
            value(Token::Ne, tag("!=")),
            value(Token::Le, tag("<=")),
            value(Token::Caret, tag("**")),
        )),
        alt((
            value(Token::Ge, tag(">=")),
            value(Token::GtGt, tag(">>")),
            value(Token::And, tag("&&")),
            value(Token::Or, tag("||")),
            value(Token::NotMatch, tag("!~")),
            value(Token::PipeAmp, tag("|&")),
            value(Token::Match, char('~')),
            // Single-char operators
            value(Token::Plus, char('+')),
            value(Token::Minus, char('-')),
            value(Token::Star, char('*')),
            value(Token::Slash, char('/')),
            value(Token::Percent, char('%')),
        )),
        alt((
            value(Token::Caret, char('^')),
            value(Token::Assign, char('=')),
            value(Token::Lt, char('<')),
            value(Token::Gt, char('>')),
            value(Token::Not, char('!')),
        )),
    ))(input)
}

fn parse_delimiter(input: &str) -> IResult<&str, Token> {
    alt((
        value(Token::LParen, char('(')),
        value(Token::RParen, char(')')),
        value(Token::LBracket, char('[')),
        value(Token::RBracket, char(']')),
        value(Token::LBrace, char('{')),
        value(Token::RBrace, char('}')),
        value(Token::Semicolon, char(';')),
        value(Token::Comma, char(',')),
        value(Token::Dollar, char('$')),
        value(Token::Question, char('?')),
        value(Token::Colon, char(':')),
        value(Token::Dot, char('.')),
        value(Token::Pipe, char('|')),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_simple_program() {
        let tokens = Lexer::tokenize("{ print $0 }").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::LBrace,
                Token::Print,
                Token::Dollar,
                Token::Number(0.0),
                Token::RBrace,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_tokenize_begin_end() {
        let tokens = Lexer::tokenize("BEGIN { print \"hello\" } END { print \"bye\" }").unwrap();
        assert!(tokens.contains(&Token::Begin));
        assert!(tokens.contains(&Token::End));
        assert!(tokens.contains(&Token::StringLiteral("hello".to_string())));
        assert!(tokens.contains(&Token::StringLiteral("bye".to_string())));
    }

    #[test]
    fn test_tokenize_numbers() {
        let tokens = Lexer::tokenize("42 5.5 1e10").unwrap();
        assert_eq!(tokens[0], Token::Number(42.0));
        assert_eq!(tokens[1], Token::Number(5.5));
        assert_eq!(tokens[2], Token::Number(1e10));
    }

    #[test]
    fn test_tokenize_string_escapes() {
        let tokens = Lexer::tokenize(r#""hello\nworld""#).unwrap();
        assert_eq!(tokens[0], Token::StringLiteral("hello\nworld".to_string()));
    }

    #[test]
    fn test_tokenize_regex() {
        let tokens = Lexer::tokenize("/foo|bar/").unwrap();
        assert_eq!(tokens[0], Token::Regex("foo|bar".to_string()));
    }

    #[test]
    fn test_tokenize_operators() {
        let tokens = Lexer::tokenize("+= -= == != <= >= && || ++ --").unwrap();
        assert_eq!(tokens[0], Token::PlusAssign);
        assert_eq!(tokens[1], Token::MinusAssign);
        assert_eq!(tokens[2], Token::Eq);
        assert_eq!(tokens[3], Token::Ne);
        assert_eq!(tokens[4], Token::Le);
        assert_eq!(tokens[5], Token::Ge);
        assert_eq!(tokens[6], Token::And);
        assert_eq!(tokens[7], Token::Or);
        assert_eq!(tokens[8], Token::Increment);
        assert_eq!(tokens[9], Token::Decrement);
    }

    #[test]
    fn test_tokenize_keywords() {
        let tokens =
            Lexer::tokenize("if else while for in delete print printf next break continue")
                .unwrap();
        assert_eq!(tokens[0], Token::If);
        assert_eq!(tokens[1], Token::Else);
        assert_eq!(tokens[2], Token::While);
        assert_eq!(tokens[3], Token::For);
        assert_eq!(tokens[4], Token::In);
        assert_eq!(tokens[5], Token::Delete);
        assert_eq!(tokens[6], Token::Print);
        assert_eq!(tokens[7], Token::Printf);
        assert_eq!(tokens[8], Token::Next);
        assert_eq!(tokens[9], Token::Break);
        assert_eq!(tokens[10], Token::Continue);
    }

    #[test]
    fn test_tokenize_special_vars() {
        let tokens = Lexer::tokenize("NF NR FS RS OFS ORS").unwrap();
        assert_eq!(tokens[0], Token::NF);
        assert_eq!(tokens[1], Token::NR);
        assert_eq!(tokens[2], Token::FS);
        assert_eq!(tokens[3], Token::RS);
        assert_eq!(tokens[4], Token::OFS);
        assert_eq!(tokens[5], Token::ORS);
    }

    #[test]
    fn test_tokenize_comment() {
        let tokens = Lexer::tokenize("{ print $0 } # this is a comment").unwrap();
        assert_eq!(
            tokens,
            vec![
                Token::LBrace,
                Token::Print,
                Token::Dollar,
                Token::Number(0.0),
                Token::RBrace,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn test_input_size_limit() {
        // Create input larger than MAX_INPUT_SIZE (10MB)
        let large_input = "x".repeat(11_000_000);
        let result = Lexer::tokenize(&large_input);
        assert!(result.is_err(), "input exceeding 10MB should be rejected");
    }

    // --- Error handling and edge case tests ---

    #[test]
    fn test_unterminated_string() {
        let result = Lexer::tokenize("\"hello");
        assert!(result.is_err(), "unterminated string should produce an error");
    }

    #[test]
    fn test_invalid_escape() {
        // Behavior for invalid escapes: either error or pass-through
        let result = Lexer::tokenize("\"\\q\"");
        // Most AWK implementations pass through unknown escapes
        // Just verify it does not panic
        let _ = result;
    }

    #[test]
    fn test_empty_input() {
        let tokens = Lexer::tokenize("").unwrap();
        assert_eq!(tokens.len(), 1, "empty input should produce just Eof");
        assert_eq!(tokens[0], Token::Eof);
    }

    #[test]
    fn test_hex_number() {
        let tokens = Lexer::tokenize("0x1F").unwrap();
        assert_eq!(tokens[0], Token::Number(31.0));
    }

    #[test]
    fn test_octal_number() {
        // This lexer does not interpret leading-zero octal; 0777 is parsed as 777.0
        let tokens = Lexer::tokenize("0777").unwrap();
        assert_eq!(tokens[0], Token::Number(777.0));
    }

    #[test]
    fn test_empty_regex() {
        let tokens = Lexer::tokenize("//").unwrap();
        assert_eq!(tokens[0], Token::Regex("".to_string()));
    }

    #[test]
    fn test_all_escape_types() {
        let tokens = Lexer::tokenize("\"\\t\\r\\n\\\\\\\"\\a\\b\\f\\v\"").unwrap();
        match &tokens[0] {
            Token::StringLiteral(s) => {
                assert!(s.contains('\t'), "should contain tab");
                assert!(s.contains('\r'), "should contain carriage return");
                assert!(s.contains('\n'), "should contain newline");
                assert!(s.contains('\\'), "should contain backslash");
                assert!(s.contains('\"'), "should contain double quote");
            }
            other => panic!("Expected StringLiteral, got {:?}", other),
        }
    }

}
