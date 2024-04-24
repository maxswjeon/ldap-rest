use std::collections::HashSet;

use ldap3::{Ldap, LdapError};
use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
pub struct AddCommand {
    pub dn: String,
    pub attrs: Vec<(String, HashSet<String>)>,
}

impl Command for AddCommand {
    async fn execute(&self, ldap: &mut Ldap) -> Result<Option<QueryResult>, LdapError> {
        match ldap.add(&self.dn, self.attrs.clone()).await {
            Ok(val) => Ok(Some(QueryResult::Common(val.into()))),
            Err(e) => Err(e),
        }
    }
}
