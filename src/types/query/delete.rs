use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteCommand {
    pub dn: String,
}

impl Command for DeleteCommand {
    async fn execute(
        &self,
        ldap: &mut ldap3_serde::Ldap,
    ) -> Result<Option<QueryResult>, ldap3_serde::LdapError> {
        match ldap.delete(&self.dn).await {
            Ok(val) => Ok(Some(QueryResult::Common(val.into()))),
            Err(e) => Err(e),
        }
    }
}
