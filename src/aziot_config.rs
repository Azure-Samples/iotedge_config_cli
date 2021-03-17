#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AziotConfig {
    pub hostname: Option<String>,
    pub parent_hostname: Option<String>,
    pub aziot_keys: Option<AziotKeys>,
    pub cert_issuance: Option<CertIssuance>,
    pub provisioning: Option<Provisioning>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AziotKeys {
    pub pkcs11_base_slot: String,
    pub pkcs11_lib_path: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CertIssuance {
    pub est: Option<Est>,
    pub local_ca: Option<LocalCa>,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Est {
    pub trusted_certs: Vec<String>,
    pub auth: Auth,
    pub urls: Urls,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Auth {
    pub bootstrap_identity_cert: String,
    pub bootstrap_identity_pk: String,
    pub identity_cert: String,
    pub identity_pk: String,
    pub password: String,
    pub username: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Urls {
    pub default: String,
}

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LocalCa {
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
