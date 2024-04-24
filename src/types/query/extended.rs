use super::{Command, Exop, QueryResult};

impl Command for Exop {
    async fn execute(
        &self,
        ldap: &mut ldap3::Ldap,
    ) -> Result<Option<QueryResult>, ldap3::LdapError> {
        match ldap.extended(self.clone()).await {
            Ok(val) => Ok(Some(QueryResult::Extended(val))),
            Err(e) => Err(e),
        }
    }
}
