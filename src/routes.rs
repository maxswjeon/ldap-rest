pub mod index;
pub mod query;

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct WhoAmICommand {}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswrodModifyCommand {}

#[derive(Debug, Clone, Deserialize)]
pub struct ExtendedOperationCommand {}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub result: bool,
}
