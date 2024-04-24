use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone)]
pub struct Scope(ldap3::Scope);

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Scope, D::Error> {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "base" => Ok(Scope(ldap3::Scope::Base)),
            "one" => Ok(Scope(ldap3::Scope::OneLevel)),
            "sub" => Ok(Scope(ldap3::Scope::Subtree)),
            "0" => Ok(Scope(ldap3::Scope::Base)),
            "1" => Ok(Scope(ldap3::Scope::OneLevel)),
            "2" => Ok(Scope(ldap3::Scope::Subtree)),
            _ => Err(serde::de::Error::custom("invalid scope")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchCommand {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    pub attrs: Vec<String>,
}
