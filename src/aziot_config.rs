#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AziotConfig {
    pub hostname: String,
    pub parent_hostname: Option<String>,
    pub trust_bundle_cert: String,
    pub edge_ca: EdgeCa,
    pub provisioning: Provisioning,
    pub agent: Agent,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EdgeCa {
    pub cert: String,
    pub pk: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Provisioning {
    pub device_id: String,
    pub iothub_hostname: String,
    pub source: String,
    pub authentication: Authentication,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Authentication {
    pub method: String,
    pub device_id_pk: DeviceIdPk,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeviceIdPk {
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Agent {
    pub config: AgentConfig,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AgentConfig {
    pub image: String,
}
