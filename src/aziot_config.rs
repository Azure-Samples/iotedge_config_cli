#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AziotConfig {
    pub hostname: String,
    pub parent_hostname: Option<String>,
    pub trust_bundle_cert: String,
    pub edge_ca: EdgeCa,
    pub provisioning: Provisioning,
    pub agent: Agent,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EdgeCa {
    pub cert: String,
    pub pk: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Provisioning {
    pub device_id: String,
    pub iothub_hostname: String,
    pub source: String,
    pub authentication: ManualAuthMethod,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey { device_id_pk: DeviceIdPk },

    X509 {
        #[serde(flatten)]
        identity: X509Identity,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceIdPk {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct X509Identity {
    pub identity_cert: String,
    pub identity_pk: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Agent {
    pub config: AgentConfig,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AgentConfig {
    pub image: String,
}
