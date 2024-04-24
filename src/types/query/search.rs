use serde::{Deserialize, Deserializer};

use super::{Command, QueryResult};

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

impl Command for SearchCommand {
    async fn execute(
        &self,
        ldap: &mut ldap3::Ldap,
    ) -> Result<Option<QueryResult>, ldap3::LdapError> {
        match ldap
            .search(&self.base, self.scope.0, &self.filter, self.attrs.clone())
            .await
        {
            Ok(val) => Ok(Some(QueryResult::Search(val.into()))),
            Err(e) => Err(e),
        }
    }
}
