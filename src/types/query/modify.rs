use std::collections::HashSet;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Mod {
    Add(AddMod),
    Delete(DeleteMod),
    Replace(ReplaceMod),
    Increment(IncrementMod),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddMod {
    pub attr: String,
    pub values: HashSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteMod {
    pub attr: String,
    pub values: HashSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplaceMod {
    pub attr: String,
    pub values: HashSet<String>,
}

// TODO: IncrementMod can be used for integer values
#[derive(Debug, Clone, Deserialize)]
pub struct IncrementMod {
    pub attr: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModifyCommand {
    pub dn: String,
    pub changes: Vec<Mod>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModifyDnCommand {
    pub dn: String,
    pub rdn: String,
    pub delete_old: bool,
    pub new_superior: Option<String>,
}
