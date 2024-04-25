mod add;
mod bind;
mod compare;
mod delete;
mod extended;
mod modify;
mod pwdmod;
mod search;
mod whoami;

use self::{
    add::AddCommand,
    bind::{BindCommand, UnbindCommand},
    compare::CompareCommand,
    delete::DeleteCommand,
    modify::{ModifyCommand, ModifyDnCommand},
    pwdmod::PasswordModifyCommand,
    search::SearchCommand,
    whoami::WhoAmICommand,
};

use serde::{Deserialize, Serialize};

use ldap3_serde::{
    exop::Exop,
    result::{CompareResult, ExopResult},
    Ldap, LdapError, LdapResult, SearchResult,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'a"))]
#[serde(tag = "type")]
pub enum QueryCommand<'a> {
    #[serde(rename = "bind")]
    Bind(BindCommand),

    #[serde(rename = "unbind")]
    Unbind(UnbindCommand),

    #[serde(rename = "search")]
    Search(SearchCommand),

    #[serde(rename = "add")]
    Add(AddCommand),

    #[serde(rename = "compare")]
    Compare(CompareCommand),

    #[serde(rename = "delete")]
    Delete(DeleteCommand),

    #[serde(rename = "modify")]
    Modify(ModifyCommand),

    #[serde(rename = "modifydn")]
    ModifyDn(ModifyDnCommand),

    #[serde(rename = "whoami")]
    WhoAmI(WhoAmICommand),

    #[serde(rename = "passwd")]
    PasswordModify(PasswordModifyCommand<'a>),

    #[serde(rename = "extended")]
    ExtendedOperation(Exop),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum QueryResult {
    Common(LdapResult),
    Search(SearchResult),
    Compare(CompareResult),
    Extended(ExopResult),
}

pub trait Command {
    async fn execute(&self, ldap: &mut Ldap) -> Result<Option<QueryResult>, LdapError>;
}

impl<'a> Command for QueryCommand<'a> {
    async fn execute(&self, ldap: &mut Ldap) -> Result<Option<QueryResult>, LdapError> {
        match self {
            QueryCommand::Bind(cmd) => cmd.execute(ldap).await,
            QueryCommand::Unbind(cmd) => cmd.execute(ldap).await,
            QueryCommand::Search(cmd) => cmd.execute(ldap).await,
            QueryCommand::Add(cmd) => cmd.execute(ldap).await,
            QueryCommand::Compare(cmd) => cmd.execute(ldap).await,
            QueryCommand::Delete(cmd) => cmd.execute(ldap).await,
            QueryCommand::Modify(cmd) => cmd.execute(ldap).await,
            QueryCommand::ModifyDn(cmd) => cmd.execute(ldap).await,
            QueryCommand::WhoAmI(cmd) => cmd.execute(ldap).await,
            QueryCommand::PasswordModify(cmd) => cmd.execute(ldap).await,
            QueryCommand::ExtendedOperation(cmd) => cmd.execute(ldap).await,
        }
    }
}
