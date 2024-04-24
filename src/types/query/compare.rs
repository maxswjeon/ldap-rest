use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CompareCommand {
    pub dn: String,
    pub attribute: String,
    pub value: String,
}
