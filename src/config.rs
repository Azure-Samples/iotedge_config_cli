#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ConfigVersion {
    pub config_version: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub iothub: IoTHub,
    pub certificates: Option<Certificates>,
    pub configuration: Configuration,
    #[serde(rename = "edgedevices")]
    pub root_device: DeviceConfig,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IoTHub {
    pub iothub_hostname: String,
    pub iothub_name: String,
    pub authentication_method: String, //TODO: Make Enum
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Certificates {
    pub root_ca_cert_path: String,
    pub root_ca_cert_key_path: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Configuration {
    pub template_config_path: String,
    pub default_edge_agent: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DeviceConfig {
    pub device_id: String,
    pub deployment: Option<String>,
    pub hostname: Option<String>,
    pub edge_agent: Option<String>,
    #[serde(default, rename = "child")]
    pub children: Vec<DeviceConfig>,
}
