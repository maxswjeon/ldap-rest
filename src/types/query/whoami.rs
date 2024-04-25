use super::{Command, QueryResult};
use ldap3_serde::exop::WhoAmI;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct WhoAmICommand {}

impl Command for WhoAmICommand {
    async fn execute(
        &self,
        ldap: &mut ldap3_serde::Ldap,
    ) -> Result<Option<QueryResult>, ldap3_serde::LdapError> {
        match ldap.extended::<WhoAmI>(WhoAmI {}).await {
            Ok(val) => Ok(Some(QueryResult::Extended(val.into()))),
            Err(e) => Err(e),
        }
    }
}
