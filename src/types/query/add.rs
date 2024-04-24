use std::collections::HashSet;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AddCommand {
    pub dn: String,
    pub attrs: Vec<(String, HashSet<String>)>,
}
