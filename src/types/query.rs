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

use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use ldap3::{controls::ControlType::*, result::ExopResult, LdapError, SearchResult};
use ldap3::{result::CompareResult, Ldap};

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

#[derive(Debug, Clone)]
pub struct Exop(ldap3::exop::Exop);

impl From<ldap3::exop::Exop> for Exop {
    fn from(e: ldap3::exop::Exop) -> Self {
        Exop(e)
    }
}

impl Into<ldap3::exop::Exop> for Exop {
    fn into(self) -> ldap3::exop::Exop {
        self.0
    }
}

impl Serialize for Exop {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = serializer.serialize_struct("Exop", 2)?;
        ser.serialize_field("name", &self.0.name)?;
        ser.serialize_field("value", &self.0.val)?;
        ser.end()
    }
}

impl<'de> Deserialize<'de> for Exop {
    fn deserialize<D>(deserializer: D) -> Result<Exop, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ExopHelper {
            name: Option<String>,
            value: Option<Vec<u8>>,
        }

        let helper = ExopHelper::deserialize(deserializer)?;
        Ok(Exop(ldap3::exop::Exop {
            name: helper.name,
            val: helper.value,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ResultEntry(ldap3::ResultEntry);

impl From<ldap3::ResultEntry> for ResultEntry {
    fn from(e: ldap3::ResultEntry) -> Self {
        ResultEntry(e)
    }
}

impl Into<ldap3::ResultEntry> for ResultEntry {
    fn into(self) -> ldap3::ResultEntry {
        self.0
    }
}

impl Serialize for ResultEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = serializer.serialize_struct("ResultEntry", 2)?;
        ser.serialize_field("structure_tags", &StructureTag::from(self.0 .0.clone()))?;
        ser.serialize_field(
            "controls",
            &self.0 .1.iter().map(|c| c.into()).collect::<Vec<Control>>(),
        )?;
        ser.end()
    }
}

#[derive(Debug, Clone)]
pub struct StructureTag(ldap3::asn1::StructureTag);

impl From<ldap3::asn1::StructureTag> for StructureTag {
    fn from(st: ldap3::asn1::StructureTag) -> Self {
        StructureTag(st)
    }
}

impl Into<ldap3::asn1::StructureTag> for StructureTag {
    fn into(self) -> ldap3::asn1::StructureTag {
        self.0
    }
}

impl Serialize for StructureTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let class = match self.0.class {
            ldap3::asn1::TagClass::Universal => "universal",
            ldap3::asn1::TagClass::Application => "application",
            ldap3::asn1::TagClass::Context => "context",
            ldap3::asn1::TagClass::Private => "private",
        };

        let mut ser = serializer.serialize_struct("StructureTag", 3)?;
        ser.serialize_field("class", class)?;
        ser.serialize_field("id", &self.0.id)?;
        ser.serialize_field("payload", &PL::from(self.0.payload.clone()))?;
        ser.end()
    }
}

#[derive(Debug, Clone)]
pub struct PL(ldap3::asn1::PL);

impl From<ldap3::asn1::PL> for PL {
    fn from(pl: ldap3::asn1::PL) -> Self {
        PL(pl)
    }
}

impl Into<ldap3::asn1::PL> for PL {
    fn into(self) -> ldap3::asn1::PL {
        self.0
    }
}

impl Serialize for PL {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            ldap3::asn1::PL::P(ref p) => p.serialize(serializer),
            ldap3::asn1::PL::C(ref c) => c
                .into_iter()
                .map(|e| e.clone().into())
                .collect::<Vec<StructureTag>>()
                .serialize(serializer),
        }
    }
}

#[derive(Debug, Clone)]
pub enum QueryResult {
    Common(LdapResult),
    Search(SearchResult),
    Compare(CompareResult),
    Extended(ExopResult),
}

impl Serialize for QueryResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            QueryResult::Common(r) => {
                let mut ser = serializer.serialize_struct("Result", 1)?;
                ser.serialize_field("result", r)?;
                ser.end()
            }
            QueryResult::Search(r) => {
                let mut ser = serializer.serialize_struct("SearchResult", 2)?;
                ser.serialize_field("result", &LdapResult::from(r.1.clone()))?;
                ser.serialize_field(
                    "data",
                    &r.0.clone()
                        .into_iter()
                        .map(|c| ResultEntry::from(c))
                        .collect::<Vec<ResultEntry>>(),
                )?;
                ser.end()
            }
            QueryResult::Compare(r) => {
                let mut ser = serializer.serialize_struct("CompareResult", 1)?;
                ser.serialize_field("result", &LdapResult::from(r.0.clone()))?;
                ser.end()
            }
            QueryResult::Extended(r) => {
                let mut ser = serializer.serialize_struct("ExtendedResult", 2)?;
                ser.serialize_field("result", &LdapResult::from(r.1.clone()))?;
                ser.serialize_field("operation", &Exop::from(r.0.clone()))?;
                ser.end()
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LdapResult {
    pub rc: u32,
    pub matched: String,
    pub text: String,
    pub refs: Vec<String>,
    pub ctrls: Vec<Control>,
}

impl From<ldap3::LdapResult> for LdapResult {
    fn from(r: ldap3::LdapResult) -> Self {
        LdapResult {
            rc: r.rc,
            matched: r.matched,
            text: r.text,
            refs: r.refs,
            ctrls: r.ctrls.into_iter().map(|c| c.into()).collect(),
        }
    }
}

impl Into<ldap3::LdapResult> for LdapResult {
    fn into(self) -> ldap3::LdapResult {
        ldap3::LdapResult {
            rc: self.rc,
            matched: self.matched,
            text: self.text,
            refs: self.refs,
            ctrls: self.ctrls.into_iter().map(|c| c.into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Control(pub Option<ControlType>, pub RawControl);

impl From<ldap3::controls::Control> for Control {
    fn from(c: ldap3::controls::Control) -> Self {
        match c.0 {
            Some(ct) => Control(Some(ct.into()), c.1.into()),
            None => Control(None, c.1.into()),
        }
    }
}

impl From<&ldap3::controls::Control> for Control {
    fn from(c: &ldap3::controls::Control) -> Self {
        match c.0 {
            Some(ct) => Control(Some(ct.into()), c.1.clone().into()),
            None => Control(None, c.1.clone().into()),
        }
    }
}

impl Into<ldap3::controls::Control> for Control {
    fn into(self) -> ldap3::controls::Control {
        match self.0 {
            Some(ct) => ldap3::controls::Control(Some(ct.into()), self.1.into()),
            None => ldap3::controls::Control(None, self.1.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RawControl {
    ctype: String,
    crit: bool,
    val: Option<Vec<u8>>,
}

impl From<ldap3::controls::RawControl> for RawControl {
    fn from(rc: ldap3::controls::RawControl) -> Self {
        RawControl {
            ctype: rc.ctype,
            crit: rc.crit,
            val: rc.val,
        }
    }
}

impl Into<ldap3::controls::RawControl> for RawControl {
    fn into(self) -> ldap3::controls::RawControl {
        ldap3::controls::RawControl {
            ctype: self.ctype,
            crit: self.crit,
            val: self.val,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ControlType {
    inner: ldap3::controls::ControlType,
}

impl From<ldap3::controls::ControlType> for ControlType {
    fn from(ct: ldap3::controls::ControlType) -> Self {
        ControlType { inner: ct }
    }
}

impl Into<ldap3::controls::ControlType> for ControlType {
    fn into(self) -> ldap3::controls::ControlType {
        self.inner
    }
}

impl Serialize for ControlType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.inner {
            PagedResults => serializer.serialize_str("1.2.840.113556.1.4.319"),
            PreReadResp => serializer.serialize_str("1.3.6.1.1.13.1"),
            PostReadResp => serializer.serialize_str("1.3.6.1.1.13.2"),
            SyncDone => serializer.serialize_str("1.3.6.1.4.1.4203.1.9.1.3"),
            SyncState => serializer.serialize_str("1.3.6.1.4.1.4203.1.9.1.2"),
            ManageDsaIt => serializer.serialize_str("2.16.840.1.113730.3.4.2"),
            MatchedValues => serializer.serialize_str("1.2.826.0.1.3344810.2.3"),
            _ => serializer.serialize_none(),
        }
    }
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
