//! Built-in AWK functions.
//!
//! Only math functions are dispatched through this module.
//! String functions (length, substr, split, sub, gsub, etc.) are
//! handled inline by the evaluator for performance.

pub struct BuiltinFunctions;

impl BuiltinFunctions {
    pub fn atan2(y: f64, x: f64) -> f64 {
        y.atan2(x)
    }

    pub fn cos(x: f64) -> f64 {
        x.cos()
    }

    pub fn sin(x: f64) -> f64 {
        x.sin()
    }

    pub fn exp(x: f64) -> f64 {
        x.exp()
    }

    pub fn log(x: f64) -> f64 {
        x.ln()
    }

    pub fn sqrt(x: f64) -> f64 {
        x.sqrt()
    }

    pub fn int(x: f64) -> f64 {
        x.trunc()
    }
}
