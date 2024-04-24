use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BindCommand {
    pub dn: String,
    pub pw: String,
}
