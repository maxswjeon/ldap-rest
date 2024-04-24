use ldap3::LdapError;
use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
pub struct CompareCommand {
    pub dn: String,
    pub attribute: String,
    pub value: String,
}

impl Command for CompareCommand {
    async fn execute(&self, ldap: &mut ldap3::Ldap) -> Result<Option<QueryResult>, LdapError> {
        match ldap.compare(&self.dn, &self.attribute, &self.value).await {
            Ok(val) => Ok(Some(QueryResult::Compare(val))),
            Err(e) => Err(e),
        }
    }
}
