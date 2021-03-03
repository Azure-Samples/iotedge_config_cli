#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Config {
    pub iothub: IoTHub,
    pub certificates: Certificates,
    pub configuration: Configuration,
    #[serde(rename = "edgedevices")]
    pub root_device: RootDevice,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct IoTHub {
    pub iot_hub_resource_group: String,
    pub iot_hub_name: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Certificates {
    pub root_ca_cert_path: String,
    pub root_ca_cert_key_path: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Configuration {
    pub template_config_path: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct RootDevice {
    #[serde(rename = "root")]
    pub device_id: String,
    #[serde(default, rename = "child")]
    pub children: Vec<ChildDevice>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ChildDevice {
    pub device_id: String,
    #[serde(default, rename = "child")]
    pub children: Vec<ChildDevice>,
}
