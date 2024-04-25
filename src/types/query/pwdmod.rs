use ldap3_serde::exop::PasswordModify;
use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordModifyCommand<'a> {
    pub user_id: Option<&'a str>,
    pub old_pass: Option<&'a str>,
    pub new_pass: Option<&'a str>,
}

impl<'a> Into<PasswordModify<'a>> for PasswordModifyCommand<'a> {
    fn into(self) -> PasswordModify<'a> {
        PasswordModify {
            user_id: self.user_id,
            old_pass: self.old_pass,
            new_pass: self.new_pass,
        }
    }
}

impl<'a> Command for PasswordModifyCommand<'a> {
    async fn execute(
        &self,
        ldap: &mut ldap3_serde::Ldap,
    ) -> Result<Option<QueryResult>, ldap3_serde::LdapError> {
        match ldap.extended::<PasswordModify>(self.clone().into()).await {
            Ok(val) => Ok(Some(QueryResult::Extended(val.into()))),
            Err(e) => Err(e),
        }
    }
}
