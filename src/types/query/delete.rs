use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteCommand {
    pub dn: String,
}
