use std::collections::HashSet;

use serde::Deserialize;

use super::{Command, QueryResult};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Mod {
    Add(AddMod),
    Delete(DeleteMod),
    Replace(ReplaceMod),
    Increment(IncrementMod),
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddMod {
    pub attr: String,
    pub values: HashSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteMod {
    pub attr: String,
    pub values: HashSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReplaceMod {
    pub attr: String,
    pub values: HashSet<String>,
}

// TODO: IncrementMod can be used for integer values
#[derive(Debug, Clone, Deserialize)]
pub struct IncrementMod {
    pub attr: String,
    pub value: String,
}

impl Into<ldap3::Mod<String>> for Mod {
    fn into(self) -> ldap3::Mod<String> {
        match self {
            Mod::Add(add) => ldap3::Mod::Add(add.attr, add.values.into_iter().collect()),
            Mod::Delete(delete) => {
                ldap3::Mod::Delete(delete.attr, delete.values.into_iter().collect())
            }
            Mod::Replace(replace) => {
                ldap3::Mod::Replace(replace.attr, replace.values.into_iter().collect())
            }
            Mod::Increment(increment) => {
                ldap3::Mod::Increment(increment.attr, increment.value.parse().unwrap())
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModifyCommand {
    pub dn: String,
    pub changes: Vec<Mod>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModifyDnCommand {
    pub dn: String,
    pub rdn: String,
    pub delete_old: bool,
    pub new_superior: Option<String>,
}

impl Command for ModifyCommand {
    async fn execute(
        &self,
        ldap: &mut ldap3::Ldap,
    ) -> Result<Option<QueryResult>, ldap3::LdapError> {
        match ldap
            .modify(
                &self.dn,
                self.changes.clone().into_iter().map(|m| m.into()).collect(),
            )
            .await
        {
            Ok(val) => Ok(Some(QueryResult::Common(val.into()))),
            Err(e) => Err(e),
        }
    }
}

impl Command for ModifyDnCommand {
    async fn execute(
        &self,
        ldap: &mut ldap3::Ldap,
    ) -> Result<Option<QueryResult>, ldap3::LdapError> {
        match ldap
            .modifydn(
                &self.dn,
                &self.rdn,
                self.delete_old,
                self.new_superior.as_deref(),
            )
            .await
        {
            Ok(val) => Ok(Some(QueryResult::Common(val.into()))),
            Err(e) => Err(e),
        }
    }
}
