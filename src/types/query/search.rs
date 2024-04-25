use serde::{Deserialize, Serialize};

use ldap3_serde::{LdapError, Scope};

use super::{Command, QueryResult};

#[derive(Serialize, Deserialize)]
#[serde(remote = "Scope")]
pub enum ScopeDef {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchCommand {
    pub base: String,
    #[serde(with = "ScopeDef")]
    pub scope: Scope,
    pub filter: String,
    pub attrs: Vec<String>,
}

impl Command for SearchCommand {
    async fn execute(
        &self,
        ldap: &mut ldap3_serde::Ldap,
    ) -> Result<Option<QueryResult>, LdapError> {
        match ldap
            .search(&self.base, self.scope, &self.filter, self.attrs.clone())
            .await
        {
            Ok(val) => Ok(Some(QueryResult::Search(val.into()))),
            Err(e) => Err(e),
        }
    }
}
