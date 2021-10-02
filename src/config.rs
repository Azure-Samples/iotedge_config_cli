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
    pub root_device: Vec<EdgeDeviceConfig>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IoTHub {
    pub iothub_hostname: String,
    pub iothub_name: String,
    pub authentication_method: IoTHubAuthMethod,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub enum IoTHubAuthMethod {
    #[serde(rename = "symmetric_key")]
    SymmetricKey,
    #[serde(rename = "x509_certificate")]
    X509Cert,
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
pub struct EdgeDeviceConfig {
    pub device_id: String,
    pub deployment: Option<String>,
    pub hostname: Option<String>,
    pub edge_agent: Option<String>,
    pub container_auth: Option<ContainerAuth>,
    #[serde(default, rename = "child")]
    pub children: Vec<EdgeDeviceConfig>,
    #[serde(default, rename = "leaf")]
    pub leaves: Vec<LeafDeviceConfig>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct LeafDeviceConfig {
    pub device_id: String,
    pub deployment: Option<String>,
}


#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ContainerAuth {
    pub serveraddress: String,
    pub username: String,
    pub password: String,
}
