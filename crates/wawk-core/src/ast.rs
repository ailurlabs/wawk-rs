//! Abstract Syntax Tree (AST) definitions for the AWK language.
//!
//! This module defines all the types needed to represent a parsed AWK program.

/// A complete AWK program consisting of rules and function definitions.
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    pub rules: Vec<Rule>,
    pub functions: Vec<FunctionDef>,
}

/// A user-defined function.
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDef {
    pub name: String,
    pub params: Vec<String>,
    pub locals: Vec<String>,
    pub body: ActionBlock,
}

/// A rule is an optional pattern followed by an action block.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub pattern: Option<Pattern>,
    pub action: Option<ActionBlock>,
}

/// Patterns that determine when a rule's action is executed.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// BEGIN block - runs before any input is read
    Begin,
    /// END block - runs after all input is processed
    End,
    /// A regex pattern /pattern/
    Regex(String),
    /// An expression that evaluates to true/false
    Expression(Expr),
    /// A range pattern: pat1, pat2
    Range(Box<Pattern>, Box<Pattern>),
}

/// A block of statements enclosed in braces.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionBlock {
    pub statements: Vec<Statement>,
}

/// The type of I/O redirection for print/printf statements.
#[derive(Debug, Clone, PartialEq)]
pub enum RedirectionType {
    /// `> file` - truncate and write
    ToFile,
    /// `>> file` - append and write
    AppendToFile,
    /// `| cmd` - pipe output to command
    Pipe,
}

/// The source for a getline statement.
#[derive(Debug, Clone, PartialEq)]
pub enum GetlineSource {
    /// `getline [var]` - read next input record
    Default,
    /// `getline [var] < file` - read from file
    File(Box<Expr>),
    /// `getline [var] | cmd` - read from command pipe
    Pipe(Box<Expr>),
}

/// Statements that can appear in an action block.
#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    /// print expr, expr, ...
    Print(Vec<Expr>),
    /// print expr, ... > file / >> file | cmd
    PrintRedirect(Vec<Expr>, RedirectionType, Expr),
    /// printf format, expr, ...
    Printf(Expr, Vec<Expr>),
    /// printf format, expr, ... > file / >> file | cmd
    PrintfRedirect(Expr, Vec<Expr>, RedirectionType, Expr),
    /// if (cond) stmt [else stmt]
    If(Expr, Box<Statement>, Option<Box<Statement>>),
    /// while (cond) stmt
    While(Expr, Box<Statement>),
    /// for (init; cond; incr) stmt
    For(
        Option<Box<Statement>>,
        Option<Box<Expr>>,
        Option<Box<Expr>>,
        Box<Statement>,
    ),
    /// for (var in array) stmt
    ForIn(String, String, Box<Statement>),
    /// A block of statements
    Block(Vec<Statement>),
    /// Variable assignment: var = expr
    Assign(String, Expr),
    /// Array element assignment: arr[idx] = expr
    ArrayAssign(String, Expr, Expr),
    /// Field assignment: $expr = value
    FieldAssign(Expr, Expr),
    /// Compound assignment: var op= expr
    CompoundAssign(String, BinOp, Expr),
    /// Increment/decrement: var++ or var--
    Increment(String, bool), // true = increment, false = decrement
    /// Expression statement
    Expr(Expr),
    /// next statement - skip to next input record
    Next,
    /// nextfile statement - skip to next input file
    NextFile,
    /// break statement
    Break,
    /// continue statement
    Continue,
    /// return [expr]
    Return(Option<Expr>),
    /// delete array[index]
    Delete(String, Expr),
    /// delete array (entire array)
    DeleteAll(String),
    /// close(expr) - close a file or pipe
    Close(Expr),
    /// getline [var] [< file | cmd]
    Getline(Option<String>, GetlineSource),
}

/// Expressions in the AWK language.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Numeric literal
    Number(f64),
    /// String literal
    String(String),
    /// Variable reference
    Var(String),
    /// Field reference: $n
    Field(Box<Expr>),
    /// $0 - the entire record
    Record,
    /// Binary operation
    BinOp(Box<Expr>, BinOp, Box<Expr>),
    /// Unary operation
    UnaryOp(UnaryOp, Box<Expr>),
    /// Function call: name(args)
    FuncCall(String, Vec<Expr>),
    /// Array subscript: arr[idx]
    ArrayAccess(String, Box<Expr>),
    /// Comparison (used in patterns)
    Match(Box<Expr>, String), // expr ~ /regex/
    NotMatch(Box<Expr>, String), // expr !~ /regex/
    /// Ternary: cond ? then : else
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    /// String concatenation (juxtaposition)
    Concat(Vec<Expr>),
    /// Post-increment expression (var++ / var--)
    PostIncrement(Box<Expr>, bool), // true = ++, false = --
    /// Pre-increment expression (++var / --var)
    PreIncrement(Box<Expr>, bool), // true = ++, false = --
    /// Assignment expression (used in some contexts)
    AssignExpr(String, Box<Expr>),
    /// getline expression: returns 1/0 and optionally sets a variable
    GetlineExpr(Option<String>, GetlineSource),
    /// Boolean literal: true or false
    BoolLit(bool),
    /// Null literal
    NullLit,
    /// Object literal: {"key": expr, ...}
    ObjectLit(Vec<(String, Expr)>),
    /// Array literal: [expr, expr, ...]
    ArrayLit(Vec<Expr>),
    /// Dot access: expr.field
    DotAccess(Box<Expr>, String),
    /// Index access on expression: expr[expr] (for arrays/objects as values)
    IndexExpr(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// Returns true if this expression is a leaf node (contains no sub-expressions).
    /// Leaf nodes never recursively call eval_expr, so depth checks can be skipped.
    #[inline(always)]
    pub fn is_leaf(&self) -> bool {
        matches!(self, Expr::Number(_) | Expr::String(_) | Expr::Var(_)
            | Expr::Record | Expr::BoolLit(_) | Expr::NullLit)
    }
}

/// Binary operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    In(String), // array membership test: expr in array
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
    Pos,
}
