use ldap3::{Ldap, LdapError};
use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
pub struct BindCommand {
    pub dn: String,
    pub pw: String,
}

impl Command for BindCommand {
    async fn execute(&self, ldap: &mut Ldap) -> Result<Option<QueryResult>, LdapError> {
        match ldap.simple_bind(&self.dn, &self.pw).await {
            Ok(val) => Ok(Some(QueryResult::Common(val.into()))),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UnbindCommand {}

impl Command for UnbindCommand {
    async fn execute(&self, ldap: &mut Ldap) -> Result<Option<QueryResult>, LdapError> {
        match ldap.unbind().await {
            Ok(()) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
