mod add;
mod bind;
mod compare;
mod delete;
mod modify;
mod search;

use serde::Deserialize;

use self::{
    add::AddCommand,
    bind::BindCommand,
    compare::CompareCommand,
    delete::DeleteCommand,
    modify::{ModifyCommand, ModifyDnCommand},
    search::SearchCommand,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum QueryCommand {
    #[serde(rename = "bind")]
    Bind(BindCommand),

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
    WhoAmI,

    #[serde(rename = "passwd")]
    PasswordModify,

    #[serde(rename = "extended")]
    ExtendedOperation,
}
