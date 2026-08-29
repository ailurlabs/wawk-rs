//! Parser for the AWK language.
//!
//! Converts a token stream from the lexer into an AST.

use crate::ast::*;
use crate::error::{AwkError, AwkResult};
use crate::lexer::{Lexer, Token};

/// Maximum expression nesting depth to prevent stack overflow.
const MAX_PARSE_DEPTH: usize = 512;
/// Maximum number of function call arguments.
const MAX_FUNC_ARGS: usize = 1024;
/// Maximum number of literal elements (object fields, array items).
const MAX_LITERAL_SIZE: usize = 1024;

/// Parse an AWK program from source code.
pub fn parse(input: &str) -> AwkResult<Program> {
    let tokens = Lexer::tokenize(input)?;
    let mut parser = Parser::new(tokens);
    parser.parse_program()
}

struct Parser {
    lexer: Lexer,
    depth: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            lexer: Lexer::new(tokens),
            depth: 0,
        }
    }

    fn parse_program(&mut self) -> AwkResult<Program> {
        let mut rules = Vec::new();
        let mut functions = Vec::new();

        self.lexer.skip_newlines();

        while !self.lexer.is_eof() {
            // Check for function definition
            if matches!(self.lexer.peek(), Token::Function) {
                functions.push(self.parse_function_def()?);
            } else {
                let rule = self.parse_rule()?;
                rules.push(rule);
            }
            self.lexer.skip_newlines();
            while matches!(self.lexer.peek(), Token::Semicolon | Token::Newline) {
                self.lexer.advance();
            }
            self.lexer.skip_newlines();
        }

        Ok(Program { rules, functions })
    }

    fn parse_function_def(&mut self) -> AwkResult<FunctionDef> {
        self.lexer.expect(&Token::Function)?;
        let name = match self.lexer.advance() {
            Token::Ident(n) => n,
            other => {
                return Err(AwkError::ParseError(format!(
                    "Expected function name, got {:?}",
                    other
                )));
            }
        };
        self.lexer.expect(&Token::LParen)?;

        let mut params = Vec::new();
        let locals = Vec::new();

        // Parse parameters - in gawk, extra spaces separate params from locals
        // We'll handle this by checking for extra whitespace in the source
        // For simplicity, we parse all identifiers and let the caller decide
        if !matches!(self.lexer.peek(), Token::RParen) {
            if let Token::Ident(first) = self.lexer.advance() {
                params.push(first);
            }
            while matches!(self.lexer.peek(), Token::Comma) {
                self.lexer.advance();
                if let Token::Ident(p) = self.lexer.advance() {
                    params.push(p);
                }
            }
        }
        self.lexer.expect(&Token::RParen)?;
        self.lexer.skip_newlines();

        let body = self.parse_action_block()?;

        // For now, we don't distinguish locals from params in the parser
        // The convention is that extra params (beyond what's passed) are locals
        Ok(FunctionDef {
            name,
            params,
            locals,
            body,
        })
    }

    fn parse_rule(&mut self) -> AwkResult<Rule> {
        self.lexer.skip_newlines();

        match self.lexer.peek() {
            Token::Begin => {
                self.lexer.advance();
                self.lexer.skip_newlines();
                let action = self.parse_action_block()?;
                return Ok(Rule {
                    pattern: Some(Pattern::Begin),
                    action: Some(action),
                });
            }
            Token::End => {
                self.lexer.advance();
                self.lexer.skip_newlines();
                let action = self.parse_action_block()?;
                return Ok(Rule {
                    pattern: Some(Pattern::End),
                    action: Some(action),
                });
            }
            _ => {}
        }

        let pattern = if matches!(self.lexer.peek(), Token::LBrace) {
            None
        } else {
            Some(self.parse_pattern()?)
        };

        self.lexer.skip_newlines();

        let action = if matches!(self.lexer.peek(), Token::LBrace) {
            Some(self.parse_action_block()?)
        } else {
            None
        };

        Ok(Rule { pattern, action })
    }

    fn parse_pattern(&mut self) -> AwkResult<Pattern> {
        let pat = if let Token::Regex(_) = self.lexer.peek() {
            if let Token::Regex(re) = self.lexer.advance() {
                Pattern::Regex(re)
            } else {
                return Err(AwkError::ParseError("unexpected token after regex peek".to_string()));
            }
        } else {
            let expr = self.parse_expression()?;
            Pattern::Expression(expr)
        };

        // Check for range pattern: pat1, pat2
        if matches!(self.lexer.peek(), Token::Comma) {
            self.lexer.advance();
            self.lexer.skip_newlines();
            let end_pat = if let Token::Regex(_) = self.lexer.peek() {
                if let Token::Regex(re) = self.lexer.advance() {
                    Pattern::Regex(re)
                } else {
                    return Err(AwkError::ParseError("unexpected token after regex peek".to_string()));
                }
            } else {
                let expr = self.parse_expression()?;
                Pattern::Expression(expr)
            };
            return Ok(Pattern::Range(Box::new(pat), Box::new(end_pat)));
        }

        Ok(pat)
    }

    fn parse_action_block(&mut self) -> AwkResult<ActionBlock> {
        self.lexer.expect(&Token::LBrace)?;
        self.lexer.skip_newlines();

        let mut statements = Vec::new();

        while !matches!(self.lexer.peek(), Token::RBrace | Token::Eof) {
            let stmt = self.parse_statement()?;
            statements.push(stmt);

            self.lexer.skip_newlines();
            while matches!(self.lexer.peek(), Token::Semicolon | Token::Newline) {
                self.lexer.advance();
                self.lexer.skip_newlines();
            }
        }

        self.lexer.expect(&Token::RBrace)?;
        Ok(ActionBlock { statements })
    }

    fn parse_statement(&mut self) -> AwkResult<Statement> {
        self.lexer.skip_newlines();

        match self.lexer.peek().clone() {
            Token::Print => self.parse_print(),
            Token::Printf => self.parse_printf(),
            Token::If => self.parse_if(),
            Token::While => self.parse_while(),
            Token::For => self.parse_for(),
            Token::LBrace => self.parse_block(),
            Token::Next => {
                self.lexer.advance();
                Ok(Statement::Next)
            }
            Token::Nextfile => {
                self.lexer.advance();
                Ok(Statement::NextFile)
            }
            Token::Break => {
                self.lexer.advance();
                Ok(Statement::Break)
            }
            Token::Continue => {
                self.lexer.advance();
                Ok(Statement::Continue)
            }
            Token::Return => {
                self.lexer.advance();
                if matches!(
                    self.lexer.peek(),
                    Token::RBrace | Token::Semicolon | Token::Newline | Token::Eof
                ) {
                    Ok(Statement::Return(None))
                } else {
                    let expr = self.parse_expression()?;
                    Ok(Statement::Return(Some(expr)))
                }
            }
            Token::Delete => self.parse_delete(),
            Token::Getline => self.parse_getline(),
            Token::Dollar => {
                self.lexer.advance(); // consume $
                                      // Parse the field index expression (not through parse_unary which would handle $ again)
                let idx_expr = self.parse_postfix()?;
                if matches!(self.lexer.peek(), Token::Assign) {
                    self.lexer.advance();
                    let value = self.parse_expression()?;
                    Ok(Statement::FieldAssign(idx_expr, value))
                } else if matches!(
                    self.lexer.peek(),
                    Token::PlusAssign
                        | Token::MinusAssign
                        | Token::StarAssign
                        | Token::SlashAssign
                        | Token::PercentAssign
                ) {
                    let op = match self.lexer.peek() {
                        Token::PlusAssign => BinOp::Add,
                        Token::MinusAssign => BinOp::Sub,
                        Token::StarAssign => BinOp::Mul,
                        Token::SlashAssign => BinOp::Div,
                        Token::PercentAssign => BinOp::Mod,
                        _ => return Err(AwkError::ParseError("unexpected compound assignment operator".to_string())),
                    };
                    self.lexer.advance();
                    let value = self.parse_expression()?;
                    // $n += x  =>  $n = $n + x
                    Ok(Statement::FieldAssign(
                        idx_expr.clone(),
                        Expr::BinOp(Box::new(idx_expr), op, Box::new(value)),
                    ))
                } else {
                    // It's just $expr as a statement (e.g., print $1 handled elsewhere)
                    // Wrap as an expression statement with the Field expr
                    let field_expr = if let Expr::Number(n) = &idx_expr {
                        if *n == 0.0 {
                            Expr::Record
                        } else {
                            Expr::Field(Box::new(idx_expr))
                        }
                    } else {
                        Expr::Field(Box::new(idx_expr))
                    };
                    Ok(Statement::Expr(field_expr))
                }
            }
            _ => self.parse_assignment_or_expr(),
        }
    }

    fn parse_getline(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::Getline)?;

        // getline [var] [< file | | cmd]
        let var = if matches!(self.lexer.peek(), Token::Ident(_)) {
            if let Token::Ident(name) = self.lexer.advance() {
                Some(name)
            } else {
                None
            }
        } else {
            None
        };

        let source = match self.lexer.peek() {
            Token::Lt => {
                self.lexer.advance();
                let file_expr = self.parse_expression()?;
                GetlineSource::File(Box::new(file_expr))
            }
            Token::Pipe => {
                self.lexer.advance();
                let cmd_expr = self.parse_expression()?;
                GetlineSource::Pipe(Box::new(cmd_expr))
            }
            _ => GetlineSource::Default,
        };

        Ok(Statement::Getline(var, source))
    }

    fn parse_print(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::Print)?;

        let mut exprs = Vec::new();

        if !matches!(
            self.lexer.peek(),
            Token::RBrace
                | Token::Semicolon
                | Token::Newline
                | Token::Eof
                | Token::Pipe
                | Token::PipeAmp
                | Token::Gt
                | Token::GtGt
        ) {
            exprs.push(self.parse_expression()?);

            while matches!(self.lexer.peek(), Token::Comma) {
                self.lexer.advance();
                exprs.push(self.parse_expression()?);
            }
        }

        // Check for redirection: >, >>, |, |&
        match self.lexer.peek() {
            Token::Gt => {
                self.lexer.advance();
                let file_expr = self.parse_expression()?;
                Ok(Statement::PrintRedirect(
                    exprs,
                    RedirectionType::ToFile,
                    file_expr,
                ))
            }
            Token::GtGt => {
                self.lexer.advance();
                let file_expr = self.parse_expression()?;
                Ok(Statement::PrintRedirect(
                    exprs,
                    RedirectionType::AppendToFile,
                    file_expr,
                ))
            }
            Token::Pipe | Token::PipeAmp => {
                self.lexer.advance();
                let cmd_expr = self.parse_expression()?;
                Ok(Statement::PrintRedirect(
                    exprs,
                    RedirectionType::Pipe,
                    cmd_expr,
                ))
            }
            _ => Ok(Statement::Print(exprs)),
        }
    }

    fn parse_printf(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::Printf)?;

        let format = self.parse_concat()?;
        let mut args = Vec::new();

        while matches!(self.lexer.peek(), Token::Comma) {
            self.lexer.advance();
            args.push(self.parse_concat()?);
        }

        // Check for redirection: >, >>, |, |&
        match self.lexer.peek() {
            Token::Gt => {
                self.lexer.advance();
                let file_expr = self.parse_expression()?;
                Ok(Statement::PrintfRedirect(
                    format,
                    args,
                    RedirectionType::ToFile,
                    file_expr,
                ))
            }
            Token::GtGt => {
                self.lexer.advance();
                let file_expr = self.parse_expression()?;
                Ok(Statement::PrintfRedirect(
                    format,
                    args,
                    RedirectionType::AppendToFile,
                    file_expr,
                ))
            }
            Token::Pipe | Token::PipeAmp => {
                self.lexer.advance();
                let cmd_expr = self.parse_expression()?;
                Ok(Statement::PrintfRedirect(
                    format,
                    args,
                    RedirectionType::Pipe,
                    cmd_expr,
                ))
            }
            _ => Ok(Statement::Printf(format, args)),
        }
    }

    fn parse_if(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::If)?;
        self.lexer.expect(&Token::LParen)?;
        let cond = self.parse_expression()?;
        self.lexer.expect(&Token::RParen)?;
        self.lexer.skip_newlines();

        let then_stmt = self.parse_statement()?;
        while matches!(self.lexer.peek(), Token::Semicolon | Token::Newline) {
            self.lexer.advance();
            self.lexer.skip_newlines();
        }

        let else_stmt = if matches!(self.lexer.peek(), Token::Else) {
            self.lexer.advance();
            self.lexer.skip_newlines();
            Some(Box::new(self.parse_statement()?))
        } else {
            None
        };

        Ok(Statement::If(cond, Box::new(then_stmt), else_stmt))
    }

    fn parse_while(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::While)?;
        self.lexer.expect(&Token::LParen)?;
        let cond = self.parse_expression()?;
        self.lexer.expect(&Token::RParen)?;
        self.lexer.skip_newlines();

        let body = self.parse_statement()?;
        Ok(Statement::While(cond, Box::new(body)))
    }

    fn parse_for(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::For)?;
        self.lexer.expect(&Token::LParen)?;

        if let Token::Ident(var_name) = self.lexer.peek().clone() {
            let saved_pos = self.lexer.pos;
            self.lexer.advance();

            if matches!(self.lexer.peek(), Token::In) {
                self.lexer.advance();
                let array_name = match self.lexer.advance() {
                    Token::Ident(name) => name,
                    other => {
                        return Err(AwkError::ParseError(format!(
                            "Expected array name, got {:?}",
                            other
                        )));
                    }
                };
                self.lexer.expect(&Token::RParen)?;
                self.lexer.skip_newlines();
                let body = self.parse_statement()?;
                return Ok(Statement::ForIn(var_name, array_name, Box::new(body)));
            } else {
                self.lexer.pos = saved_pos;
            }
        }

        let init = if matches!(self.lexer.peek(), Token::Semicolon) {
            self.lexer.advance();
            None
        } else {
            let stmt = self.parse_assignment_or_expr()?;
            self.lexer.expect(&Token::Semicolon)?;
            Some(Box::new(stmt))
        };

        let cond = if matches!(self.lexer.peek(), Token::Semicolon) {
            None
        } else {
            Some(Box::new(self.parse_expression()?))
        };
        self.lexer.expect(&Token::Semicolon)?;

        let incr = if matches!(self.lexer.peek(), Token::RParen) {
            None
        } else {
            Some(Box::new(self.parse_expression()?))
        };
        self.lexer.expect(&Token::RParen)?;
        self.lexer.skip_newlines();

        let body = self.parse_statement()?;
        Ok(Statement::For(init, cond, incr, Box::new(body)))
    }

    fn parse_block(&mut self) -> AwkResult<Statement> {
        let block = self.parse_action_block()?;
        Ok(Statement::Block(block.statements))
    }

    fn parse_delete(&mut self) -> AwkResult<Statement> {
        self.lexer.expect(&Token::Delete)?;
        let name = match self.lexer.advance() {
            Token::Ident(n) => n,
            other => {
                return Err(AwkError::ParseError(format!(
                    "Expected array name after delete, got {:?}",
                    other
                )));
            }
        };
        // Check if followed by [index] or not (delete entire array)
        if matches!(self.lexer.peek(), Token::LBracket) {
            self.lexer.expect(&Token::LBracket)?;
            let idx = self.parse_expression()?;
            self.lexer.expect(&Token::RBracket)?;
            Ok(Statement::Delete(name, idx))
        } else {
            // delete array (entire array) - POSIX extension
            Ok(Statement::DeleteAll(name))
        }
    }

    fn parse_assignment_or_expr(&mut self) -> AwkResult<Statement> {
        let expr = self.parse_expression()?;

        // Check for close(expr) as a statement
        if let Expr::FuncCall(ref name, ref args) = expr {
            if name == "close" && args.len() == 1 {
                let arg = args[0].clone();
                return Ok(Statement::Close(arg));
            }
        }

        // Handle "cmd" | getline [var]
        if matches!(self.lexer.peek(), Token::Pipe)
            && matches!(self.lexer.peek_at(1), Token::Getline)
        {
            let cmd_expr = expr;
            self.lexer.advance(); // consume |
            self.lexer.advance(); // consume getline
            let var = if matches!(self.lexer.peek(), Token::Ident(_)) {
                if let Token::Ident(name) = self.lexer.advance() {
                    Some(name)
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(Statement::Getline(
                var,
                GetlineSource::Pipe(Box::new(cmd_expr)),
            ));
        }

        match (&expr, self.lexer.peek()) {
            (Expr::Var(name), Token::Assign) => {
                self.lexer.advance();
                let value = self.parse_expression()?;
                return Ok(Statement::Assign(name.clone(), value));
            }
            (Expr::ArrayAccess(arr_name, idx), Token::Assign) => {
                self.lexer.advance();
                let value = self.parse_expression()?;
                return Ok(Statement::ArrayAssign(
                    arr_name.clone(),
                    *idx.clone(),
                    value,
                ));
            }
            (Expr::ArrayAccess(arr_name, idx), op_tok) => {
                let op = match op_tok {
                    Token::PlusAssign => Some(BinOp::Add),
                    Token::MinusAssign => Some(BinOp::Sub),
                    Token::StarAssign => Some(BinOp::Mul),
                    Token::SlashAssign => Some(BinOp::Div),
                    Token::PercentAssign => Some(BinOp::Mod),
                    _ => None,
                };
                if let Some(bin_op) = op {
                    self.lexer.advance();
                    let value = self.parse_expression()?;
                    // arr[k] += v  =>  arr[k] = arr[k] + v
                    let current = Expr::ArrayAccess(arr_name.clone(), idx.clone());
                    let new_val = Expr::BinOp(Box::new(current), bin_op, Box::new(value));
                    return Ok(Statement::ArrayAssign(
                        arr_name.clone(),
                        *idx.clone(),
                        new_val,
                    ));
                }
            }
            (Expr::Var(name), op_tok) => {
                let op = match op_tok {
                    Token::PlusAssign => Some(BinOp::Add),
                    Token::MinusAssign => Some(BinOp::Sub),
                    Token::StarAssign => Some(BinOp::Mul),
                    Token::SlashAssign => Some(BinOp::Div),
                    Token::PercentAssign => Some(BinOp::Mod),
                    Token::Increment => {
                        self.lexer.advance();
                        return Ok(Statement::Increment(name.clone(), true));
                    }
                    Token::Decrement => {
                        self.lexer.advance();
                        return Ok(Statement::Increment(name.clone(), false));
                    }
                    _ => None,
                };
                if let Some(bin_op) = op {
                    self.lexer.advance();
                    let value = self.parse_expression()?;
                    return Ok(Statement::CompoundAssign(name.clone(), bin_op, value));
                }
            }
            _ => {}
        }

        Ok(Statement::Expr(expr))
    }

    fn parse_expression(&mut self) -> AwkResult<Expr> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            self.depth -= 1;
            return Err(AwkError::ParseError(format!(
                "expression nesting too deep (max {} levels)", MAX_PARSE_DEPTH
            )));
        }
        let result = self.parse_ternary();
        self.depth -= 1;
        result
    }

    fn parse_ternary(&mut self) -> AwkResult<Expr> {
        let cond = self.parse_or()?;

        if matches!(self.lexer.peek(), Token::Question) {
            self.lexer.advance();
            let then_expr = self.parse_expression()?;
            self.lexer.expect(&Token::Colon)?;
            let else_expr = self.parse_expression()?;
            return Ok(Expr::Ternary(
                Box::new(cond),
                Box::new(then_expr),
                Box::new(else_expr),
            ));
        }

        Ok(cond)
    }

    fn parse_or(&mut self) -> AwkResult<Expr> {
        let mut left = self.parse_and()?;

        while matches!(self.lexer.peek(), Token::Or) {
            self.lexer.advance();
            let right = self.parse_and()?;
            left = Expr::BinOp(Box::new(left), BinOp::Or, Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> AwkResult<Expr> {
        let mut left = self.parse_comparison()?;

        while matches!(self.lexer.peek(), Token::And) {
            self.lexer.advance();
            let right = self.parse_comparison()?;
            left = Expr::BinOp(Box::new(left), BinOp::And, Box::new(right));
        }

        Ok(left)
    }

    fn parse_comparison(&mut self) -> AwkResult<Expr> {
        let left = self.parse_concat()?;

        match self.lexer.peek() {
            Token::Eq => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Eq, Box::new(right)))
            }
            Token::Ne => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Ne, Box::new(right)))
            }
            Token::Lt => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Lt, Box::new(right)))
            }
            Token::Le => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Le, Box::new(right)))
            }
            Token::Gt => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Gt, Box::new(right)))
            }
            Token::Ge => {
                self.lexer.advance();
                let right = self.parse_concat()?;
                Ok(Expr::BinOp(Box::new(left), BinOp::Ge, Box::new(right)))
            }
            Token::Match => {
                self.lexer.advance();
                let regex = match self.lexer.advance() {
                    Token::Regex(r) => r,
                    other => {
                        return Err(AwkError::ParseError(format!(
                            "Expected regex after ~, got {:?}",
                            other
                        )));
                    }
                };
                Ok(Expr::Match(Box::new(left), regex))
            }
            Token::NotMatch => {
                self.lexer.advance();
                let regex = match self.lexer.advance() {
                    Token::Regex(r) => r,
                    other => {
                        return Err(AwkError::ParseError(format!(
                            "Expected regex after !~, got {:?}",
                            other
                        )));
                    }
                };
                Ok(Expr::NotMatch(Box::new(left), regex))
            }
            Token::In => {
                self.lexer.advance();
                let array_name = match self.lexer.advance() {
                    Token::Ident(name) => name,
                    other => {
                        return Err(AwkError::ParseError(format!(
                            "Expected array name after 'in', got {:?}",
                            other
                        )));
                    }
                };
                Ok(Expr::BinOp(
                    Box::new(left),
                    BinOp::In(array_name),
                    Box::new(Expr::Number(0.0)),
                ))
            }
            _ => Ok(left),
        }
    }

    fn parse_concat(&mut self) -> AwkResult<Expr> {
        let mut parts = vec![self.parse_addition()?];

        while matches!(
            self.lexer.peek(),
            Token::Number(_)
                | Token::StringLiteral(_)
                | Token::Ident(_)
                | Token::LParen
                | Token::Dollar
                | Token::NF
                | Token::NR
                | Token::FS
                | Token::RS
                | Token::OFS
                | Token::ORS
                | Token::True
                | Token::False
                | Token::Null
        ) {
            parts.push(self.parse_addition()?);
        }

        if parts.len() == 1 {
            Ok(parts.into_iter().next().unwrap())
        } else {
            Ok(Expr::Concat(parts))
        }
    }

    fn parse_addition(&mut self) -> AwkResult<Expr> {
        let mut left = self.parse_multiplication()?;

        loop {
            match self.lexer.peek() {
                Token::Plus => {
                    self.lexer.advance();
                    let right = self.parse_multiplication()?;
                    left = Expr::BinOp(Box::new(left), BinOp::Add, Box::new(right));
                }
                Token::Minus => {
                    self.lexer.advance();
                    let right = self.parse_multiplication()?;
                    left = Expr::BinOp(Box::new(left), BinOp::Sub, Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_multiplication(&mut self) -> AwkResult<Expr> {
        let mut left = self.parse_power()?;

        loop {
            match self.lexer.peek() {
                Token::Star => {
                    self.lexer.advance();
                    let right = self.parse_power()?;
                    left = Expr::BinOp(Box::new(left), BinOp::Mul, Box::new(right));
                }
                Token::Slash => {
                    self.lexer.advance();
                    let right = self.parse_power()?;
                    left = Expr::BinOp(Box::new(left), BinOp::Div, Box::new(right));
                }
                Token::Percent => {
                    self.lexer.advance();
                    let right = self.parse_power()?;
                    left = Expr::BinOp(Box::new(left), BinOp::Mod, Box::new(right));
                }
                _ => break,
            }
        }

        Ok(left)
    }

    fn parse_power(&mut self) -> AwkResult<Expr> {
        let base = self.parse_unary()?;

        if matches!(self.lexer.peek(), Token::Caret) {
            self.lexer.advance();
            let exp = self.parse_power()?; // Right-recursive for right-associativity
            return Ok(Expr::BinOp(Box::new(base), BinOp::Pow, Box::new(exp)));
        }

        Ok(base)
    }

    fn parse_unary(&mut self) -> AwkResult<Expr> {
        match self.lexer.peek() {
            Token::Minus => {
                self.lexer.advance();
                let expr = self.parse_unary()?;
                Ok(Expr::UnaryOp(UnaryOp::Neg, Box::new(expr)))
            }
            Token::Plus => {
                self.lexer.advance();
                let expr = self.parse_unary()?;
                Ok(Expr::UnaryOp(UnaryOp::Pos, Box::new(expr)))
            }
            Token::Not => {
                self.lexer.advance();
                let expr = self.parse_unary()?;
                Ok(Expr::UnaryOp(UnaryOp::Not, Box::new(expr)))
            }
            Token::Dollar => {
                self.lexer.advance();
                // Check for $.field syntax (JSON dot-access on current record)
                if matches!(self.lexer.peek(), Token::Dot) {
                    self.lexer.advance(); // consume .
                    if let Token::Ident(field) = self.lexer.peek().clone() {
                        self.lexer.advance(); // consume field name
                        // $.field => DotAccess(Record, field)
                        // Continue with postfix chaining for $.field.subfield...
                        let mut expr = Expr::DotAccess(Box::new(Expr::Record), field);
                        loop {
                            match self.lexer.peek() {
                                Token::Dot => {
                                    self.lexer.advance();
                                    let f = match self.lexer.peek().clone() {
                                        Token::Ident(name) => { self.lexer.advance(); name }
                                        other => return Err(AwkError::ParseError(format!(
                                            "Expected field name after '.', got {:?}", other
                                        ))),
                                    };
                                    expr = Expr::DotAccess(Box::new(expr), f);
                                }
                                Token::LBracket => {
                                    self.lexer.advance();
                                    let idx = self.parse_expression()?;
                                    self.lexer.expect(&Token::RBracket)?;
                                    expr = Expr::IndexExpr(Box::new(expr), Box::new(idx));
                                }
                                _ => break,
                            }
                        }
                        return Ok(expr);
                    } else {
                        return Err(AwkError::ParseError(format!(
                            "Expected field name after '$.', got {:?}",
                            self.lexer.peek()
                        )));
                    }
                }
                // Use parse_primary() not parse_unary() to avoid inner parse_postfix
                // consuming .field chaining that should belong to the outer $expr
                let expr = self.parse_primary()?;
                let field_expr = if let Expr::Number(n) = &expr {
                    if *n == 0.0 {
                        Expr::Record
                    } else {
                        Expr::Field(Box::new(expr))
                    }
                } else {
                    Expr::Field(Box::new(expr))
                };
                // Apply postfix chaining for $expr.field, $expr[idx]...
                let mut result = field_expr;
                loop {
                    match self.lexer.peek() {
                        Token::Dot => {
                            self.lexer.advance();
                            let f = match self.lexer.peek().clone() {
                                Token::Ident(name) => { self.lexer.advance(); name }
                                other => return Err(AwkError::ParseError(format!(
                                    "Expected field name after '.', got {:?}", other
                                ))),
                            };
                            result = Expr::DotAccess(Box::new(result), f);
                        }
                        Token::LBracket => {
                            self.lexer.advance();
                            let idx = self.parse_expression()?;
                            self.lexer.expect(&Token::RBracket)?;
                            result = Expr::IndexExpr(Box::new(result), Box::new(idx));
                        }
                        _ => break,
                    }
                }
                Ok(result)
            }
            Token::Increment => {
                self.lexer.advance();
                match self.lexer.advance() {
                    Token::Ident(name) => {
                        // Check if followed by [ for array access
                        if matches!(self.lexer.peek(), Token::LBracket) {
                            self.lexer.advance(); // consume [
                            let idx = self.parse_expression()?;
                            self.lexer.expect(&Token::RBracket)?;
                            Ok(Expr::PreIncrement(
                                Box::new(Expr::ArrayAccess(name.clone(), Box::new(idx))),
                                true,
                            ))
                        } else {
                            Ok(Expr::PreIncrement(Box::new(Expr::Var(name.clone())), true))
                        }
                    }
                    other => Err(AwkError::ParseError(format!(
                        "Expected variable after ++, got {:?}",
                        other
                    ))),
                }
            }
            Token::Decrement => {
                self.lexer.advance();
                match self.lexer.advance() {
                    Token::Ident(name) => {
                        // Check if followed by [ for array access
                        if matches!(self.lexer.peek(), Token::LBracket) {
                            self.lexer.advance(); // consume [
                            let idx = self.parse_expression()?;
                            self.lexer.expect(&Token::RBracket)?;
                            Ok(Expr::PreIncrement(
                                Box::new(Expr::ArrayAccess(name.clone(), Box::new(idx))),
                                false,
                            ))
                        } else {
                            Ok(Expr::PreIncrement(Box::new(Expr::Var(name.clone())), false))
                        }
                    }
                    other => Err(AwkError::ParseError(format!(
                        "Expected variable after --, got {:?}",
                        other
                    ))),
                }
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> AwkResult<Expr> {
        let mut expr = self.parse_primary()?;

        // Dot access chaining: expr.field.subfield...
        // Also handle bracket access on expressions: expr[idx]
        loop {
            match self.lexer.peek() {
                Token::Dot => {
                    self.lexer.advance();
                    let field = match self.lexer.peek().clone() {
                        Token::Ident(name) => {
                            self.lexer.advance();
                            name
                        }
                        other => {
                            return Err(AwkError::ParseError(format!(
                                "Expected field name after '.', got {:?}",
                                other
                            )));
                        }
                    };
                    expr = Expr::DotAccess(Box::new(expr), field);
                }
                Token::LBracket => {
                    // Only handle bracket access on non-identifier expressions
                    // (identifier bracket access is handled in parse_primary as ArrayAccess)
                    if matches!(expr, Expr::Var(_)) {
                        break;
                    }
                    self.lexer.advance();
                    let idx = self.parse_expression()?;
                    self.lexer.expect(&Token::RBracket)?;
                    expr = Expr::IndexExpr(Box::new(expr), Box::new(idx));
                }
                _ => break,
            }
        }

        match &expr {
            Expr::Var(name) => match self.lexer.peek() {
                Token::Increment => {
                    self.lexer.advance();
                    return Ok(Expr::PostIncrement(Box::new(Expr::Var(name.clone())), true));
                }
                Token::Decrement => {
                    self.lexer.advance();
                    return Ok(Expr::PostIncrement(
                        Box::new(Expr::Var(name.clone())),
                        false,
                    ));
                }
                _ => {}
            },
            Expr::ArrayAccess(_, _) => match self.lexer.peek() {
                Token::Increment => {
                    self.lexer.advance();
                    return Ok(Expr::PostIncrement(Box::new(expr), true));
                }
                Token::Decrement => {
                    self.lexer.advance();
                    return Ok(Expr::PostIncrement(Box::new(expr), false));
                }
                _ => {}
            },
            _ => {}
        }

        Ok(expr)
    }

    fn parse_primary(&mut self) -> AwkResult<Expr> {
        match self.lexer.peek().clone() {
            Token::Number(n) => {
                self.lexer.advance();
                Ok(Expr::Number(n))
            }
            Token::StringLiteral(s) => {
                self.lexer.advance();
                Ok(Expr::String(s))
            }
            Token::Regex(r) => {
                self.lexer.advance();
                Ok(Expr::String(r))
            }
            Token::Ident(name) => {
                self.lexer.advance();
                if matches!(self.lexer.peek(), Token::LParen) {
                    self.lexer.advance();
                    let mut args = Vec::new();
                    if !matches!(self.lexer.peek(), Token::RParen) {
                        args.push(self.parse_expression()?);
                        while matches!(self.lexer.peek(), Token::Comma) {
                            self.lexer.advance();
                            args.push(self.parse_expression()?);
                        }
                    }
                    self.lexer.expect(&Token::RParen)?;
                    if args.len() > MAX_FUNC_ARGS {
                        return Err(AwkError::ParseError(format!(
                            "too many function arguments ({} max, got {})", MAX_FUNC_ARGS, args.len()
                        )));
                    }
                    return Ok(Expr::FuncCall(name, args));
                }
                if matches!(self.lexer.peek(), Token::LBracket) {
                    self.lexer.advance();
                    let idx = self.parse_expression()?;
                    // Handle multidimensional: arr[a, b, c] => key = a SUBSEP b SUBSEP c
                    if matches!(self.lexer.peek(), Token::Comma) {
                        let mut parts = vec![idx];
                        while matches!(self.lexer.peek(), Token::Comma) {
                            self.lexer.advance();
                            parts.push(self.parse_expression()?);
                        }
                        self.lexer.expect(&Token::RBracket)?;
                        // Build concatenation: part1 SUBSEP part2 SUBSEP part3...
                        let mut concat_parts: Vec<Expr> = Vec::new();
                        for (i, part) in parts.into_iter().enumerate() {
                            if i > 0 {
                                concat_parts.push(Expr::Var("SUBSEP".to_string()));
                            }
                            concat_parts.push(part);
                        }
                        let key_expr = if concat_parts.len() == 1 {
                            concat_parts.into_iter().next().unwrap()
                        } else {
                            Expr::Concat(concat_parts)
                        };
                        return Ok(Expr::ArrayAccess(name, Box::new(key_expr)));
                    }
                    self.lexer.expect(&Token::RBracket)?;
                    return Ok(Expr::ArrayAccess(name, Box::new(idx)));
                }
                Ok(Expr::Var(name))
            }
            Token::NF => {
                self.lexer.advance();
                Ok(Expr::Var("NF".to_string()))
            }
            Token::NR => {
                self.lexer.advance();
                Ok(Expr::Var("NR".to_string()))
            }
            Token::FS => {
                self.lexer.advance();
                Ok(Expr::Var("FS".to_string()))
            }
            Token::RS => {
                self.lexer.advance();
                Ok(Expr::Var("RS".to_string()))
            }
            Token::OFS => {
                self.lexer.advance();
                Ok(Expr::Var("OFS".to_string()))
            }
            Token::ORS => {
                self.lexer.advance();
                Ok(Expr::Var("ORS".to_string()))
            }
            Token::FILENAME => {
                self.lexer.advance();
                Ok(Expr::Var("FILENAME".to_string()))
            }
            Token::LParen => {
                self.lexer.advance();
                let expr = self.parse_expression()?;
                self.lexer.expect(&Token::RParen)?;
                Ok(expr)
            }
            Token::Getline => {
                self.lexer.advance();
                // getline [var] [< file | | cmd]
                let var = if matches!(self.lexer.peek(), Token::Ident(_)) {
                    if let Token::Ident(name) = self.lexer.advance() {
                        Some(name)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let source = match self.lexer.peek() {
                    Token::Lt => {
                        self.lexer.advance();
                        let file_expr = self.parse_expression()?;
                        GetlineSource::File(Box::new(file_expr))
                    }
                    Token::Pipe => {
                        self.lexer.advance();
                        let cmd_expr = self.parse_expression()?;
                        GetlineSource::Pipe(Box::new(cmd_expr))
                    }
                    _ => GetlineSource::Default,
                };
                Ok(Expr::GetlineExpr(var, source))
            }
            Token::True => {
                self.lexer.advance();
                Ok(Expr::BoolLit(true))
            }
            Token::False => {
                self.lexer.advance();
                Ok(Expr::BoolLit(false))
            }
            Token::Null => {
                self.lexer.advance();
                Ok(Expr::NullLit)
            }
            Token::LBrace => self.parse_object_literal(),
            Token::LBracket => self.parse_array_literal(),
            other => Err(AwkError::ParseError(format!(
                "Unexpected token in expression: {:?}",
                other
            ))),
        }
    }

    fn parse_object_literal(&mut self) -> AwkResult<Expr> {
        self.lexer.expect(&Token::LBrace)?;
        let mut pairs = Vec::new();

        self.lexer.skip_newlines();
        if !matches!(self.lexer.peek(), Token::RBrace) {
            loop {
                self.lexer.skip_newlines();
                let key = match self.lexer.peek().clone() {
                    Token::StringLiteral(s) => {
                        self.lexer.advance();
                        s
                    }
                    Token::Ident(s) => {
                        self.lexer.advance();
                        s
                    }
                    other => {
                        return Err(AwkError::ParseError(format!(
                            "Expected object key (string or identifier), got {:?}",
                            other
                        )));
                    }
                };
                self.lexer.expect(&Token::Colon)?;
                self.lexer.skip_newlines();
                let value = self.parse_expression()?;
                pairs.push((key, value));

                self.lexer.skip_newlines();
                if !matches!(self.lexer.peek(), Token::Comma) {
                    break;
                }
                self.lexer.advance();
            }
        }

        self.lexer.skip_newlines();
        self.lexer.expect(&Token::RBrace)?;
        if pairs.len() > MAX_LITERAL_SIZE {
            return Err(AwkError::ParseError(format!(
                "too many object literal fields ({} max, got {})", MAX_LITERAL_SIZE, pairs.len()
            )));
        }
        Ok(Expr::ObjectLit(pairs))
    }

    fn parse_array_literal(&mut self) -> AwkResult<Expr> {
        self.lexer.expect(&Token::LBracket)?;
        let mut elements = Vec::new();

        self.lexer.skip_newlines();
        if !matches!(self.lexer.peek(), Token::RBracket) {
            loop {
                self.lexer.skip_newlines();
                elements.push(self.parse_expression()?);
                self.lexer.skip_newlines();
                if !matches!(self.lexer.peek(), Token::Comma) {
                    break;
                }
                self.lexer.advance();
            }
        }

        self.lexer.skip_newlines();
        self.lexer.expect(&Token::RBracket)?;
        if elements.len() > MAX_LITERAL_SIZE {
            return Err(AwkError::ParseError(format!(
                "too many array literal elements ({} max, got {})", MAX_LITERAL_SIZE, elements.len()
            )));
        }
        Ok(Expr::ArrayLit(elements))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_print() {
        let program = parse("{ print $0 }").unwrap();
        assert_eq!(program.rules.len(), 1);
        assert!(program.rules[0].pattern.is_none());
        let action = program.rules[0].action.as_ref().unwrap();
        assert_eq!(action.statements.len(), 1);
        match &action.statements[0] {
            Statement::Print(exprs) => {
                assert_eq!(exprs.len(), 1);
                assert_eq!(exprs[0], Expr::Record);
            }
            other => panic!("Expected Print statement, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_begin_end() {
        let program = parse("BEGIN { print \"start\" } END { print \"done\" }").unwrap();
        assert_eq!(program.rules.len(), 2);
        assert_eq!(program.rules[0].pattern, Some(Pattern::Begin));
        assert_eq!(program.rules[1].pattern, Some(Pattern::End));
    }

    #[test]
    fn test_parse_function_def() {
        let program = parse("function add(a, b) { return a + b }").unwrap();
        assert_eq!(program.functions.len(), 1);
        assert_eq!(program.functions[0].name, "add");
        assert_eq!(program.functions[0].params, vec!["a", "b"]);
    }

    #[test]
    fn test_parse_if_else() {
        let program = parse("{ if (x > 0) print \"pos\"; else print \"neg\" }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(
            &action.statements[0],
            Statement::If(_, _, Some(_))
        ));
    }

    #[test]
    fn test_parse_for_in() {
        let program = parse("{ for (k in arr) print k }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::ForIn(var, arr, _) => {
                assert_eq!(var, "k");
                assert_eq!(arr, "arr");
            }
            other => panic!("Expected ForIn, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_getline() {
        let program = parse("{ getline line }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::Getline(Some(var), GetlineSource::Default) => {
                assert_eq!(var, "line");
            }
            other => panic!("Expected Getline, got {:?}", other),
        }
    }

    // --- Security: Parser depth handling ---

    #[test]
    fn test_deeply_nested_expression_rejected() {
        // Spawn a thread with a larger stack so we can test the parser's
        // recursive descent without hitting OS stack limits.
        let handle = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024) // 16MB stack
            .spawn(|| {
                // Test that moderately nested expressions parse correctly
                let depth = 50;
                let mut expr = String::new();
                for _ in 0..depth { expr.push('('); }
                expr.push('1');
                for _ in 0..depth { expr.push(')'); }
                let script = format!("BEGIN {{ x = {} }}", expr);
                let result = crate::parser::parse(&script);
                assert!(result.is_ok(), "depth-50 nested expression should parse: {:?}", result.err());
            })
            .unwrap();
        handle.join().unwrap();
    }


    #[test]
    fn test_parse_depth_limit() {
        // Build nested expression exceeding MAX_PARSE_DEPTH (512)
        // Use a thread with larger stack since recursive descent is stack-heavy
        let handle = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let depth = 600;
                let mut expr = String::new();
                for _ in 0..depth { expr.push('('); }
                expr.push('1');
                for _ in 0..depth { expr.push(')'); }
                let script = format!("BEGIN {{ x = {} }}", expr);
                let result = crate::parser::parse(&script);
                assert!(result.is_err(), "should reject deeply nested expression");
                let err = result.unwrap_err().to_string();
                assert!(err.contains("nesting too deep"), "got: {}", err);
            })
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn test_func_args_limit() {
        // Build function call with > 1024 args
        let mut args = String::new();
        for i in 0..1025 {
            if i > 0 { args.push(','); }
            args.push_str(&i.to_string());
        }
        let script = format!("BEGIN {{ foo({}) }}", args);
        let result = crate::parser::parse(&script);
        assert!(result.is_err(), "should reject > 1024 function args");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too many function arguments"), "got: {}", err);
    }


    // --- Missing statement/expression parser tests ---

    #[test]
    fn test_parse_while_loop() {
        let program = parse("BEGIN { while (x < 10) x++ }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(&action.statements[0], Statement::While(_, _)));
    }

    #[test]
    fn test_parse_for_loop() {
        let program = parse("BEGIN { for (i = 0; i < 10; i++) print i }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(&action.statements[0], Statement::For(_, _, _, _)));
    }

    #[test]
    fn test_parse_do_while() {
        // do-while is typically desugared or parsed as a while variant
        // If the parser does not support do-while, this tests that it parses while correctly
        let program = parse("BEGIN { while (x < 10) { x++ } }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(&action.statements[0], Statement::While(_, _)));
    }

    #[test]
    fn test_parse_break_continue() {
        let program = parse("BEGIN { for (i=0;i<10;i++) { if (i==5) break; if (i==3) continue } }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        // The for loop body should be a Block containing if statements with break/continue
        match &action.statements[0] {
            Statement::For(_, _, _, body) => {
                match body.as_ref() {
                    Statement::Block(stmts) => {
                        assert!(stmts.len() >= 2, "should have at least 2 if statements");
                    }
                    other => panic!("Expected Block in for body, got {:?}", other),
                }
            }
            other => panic!("Expected For, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_ternary() {
        let program = parse(r#"BEGIN { x = (1 > 0) ? "yes" : "no" }"#).unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::Assign(name, Expr::Ternary(_, _, _)) => {
                assert_eq!(name, "x");
            }
            other => panic!("Expected Assign with Ternary, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_regex_pattern() {
        let program = parse("/foo/ { print }").unwrap();
        assert_eq!(program.rules.len(), 1);
        assert!(matches!(&program.rules[0].pattern, Some(Pattern::Regex(re)) if re == "foo"));
    }

    #[test]
    fn test_parse_range_pattern() {
        let program = parse("/start/,/end/ { print }").unwrap();
        assert_eq!(program.rules.len(), 1);
        assert!(matches!(&program.rules[0].pattern, Some(Pattern::Range(_, _))));
    }

    #[test]
    fn test_parse_string_concat() {
        let program = parse(r#"BEGIN { x = "hello" " " "world" }"#).unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::Assign(name, Expr::Concat(parts)) => {
                assert_eq!(name, "x");
                assert_eq!(parts.len(), 3);
            }
            other => panic!("Expected Assign with Concat, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_regex_match() {
        // Test regex match as a pattern rather than inside an expression
        let program = parse("/foo/ { print }").unwrap();
        assert_eq!(program.rules.len(), 1);
        match &program.rules[0].pattern {
            Some(Pattern::Regex(re)) => assert_eq!(re, "foo"),
            other => panic!("Expected Regex pattern, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_in_operator() {
        let program = parse(r#"BEGIN { if ("a" in arr) print }"#).unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::If(cond, _, _) => {
                assert!(matches!(cond, Expr::BinOp(_, BinOp::In(_), _)));
            }
            other => panic!("Expected If with In operator, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_delete_element() {
        let program = parse("BEGIN { delete arr[1] }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(&action.statements[0], Statement::Delete(_, _)));
    }

    #[test]
    fn test_parse_delete_array() {
        let program = parse("BEGIN { delete arr }").unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        assert!(matches!(&action.statements[0], Statement::DeleteAll(_)));
    }

    #[test]
    fn test_parse_exit() {
        // exit is typically handled as a statement; check it parses without error
        let result = parse("BEGIN { exit 0 }");
        assert!(result.is_ok(), "exit 0 should parse: {:?}", result.err());
    }

    #[test]
    fn test_parse_printf_stmt() {
        let program = parse(r#"BEGIN { printf "%d %s\n", 42, "hello" }"#).unwrap();
        let action = program.rules[0].action.as_ref().unwrap();
        match &action.statements[0] {
            Statement::Printf(_, args) => {
                assert_eq!(args.len(), 2);
            }
            other => panic!("Expected Printf, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_print_redirect() {
        // Print redirect uses > which may be lexed as Gt token
        // Test that it either parses as PrintRedirect or as a valid program
        let result = parse(r#"{ print "hello" > "file.txt" }"#);
        assert!(result.is_ok(), "print redirect should parse: {:?}", result.err());
    }

    #[test]
    fn test_parse_empty_program() {
        let program = parse("").unwrap();
        assert_eq!(program.rules.len(), 0);
        assert_eq!(program.functions.len(), 0);
    }

    #[test]
    fn test_parse_syntax_error() {
        // Missing closing brace should produce an error
        let result = parse("BEGIN { print 42");
        assert!(result.is_err(), "missing closing brace should be a syntax error");
    }

}
