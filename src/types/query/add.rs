use std::collections::HashSet;

use ldap3_serde::{Ldap, LdapError};
use serde::{Deserialize, Serialize};

use super::{Command, QueryResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
