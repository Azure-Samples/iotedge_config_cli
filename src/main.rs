use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Local;
use structopt::StructOpt;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

mod aziot_config;
mod config;
mod hub_responses;

use config::*;
use hub_responses::*;

// Windows only, run
//$Env:OPENSSL_CONF="C:\Users\Lee\source\GnuWin32\share\openssl.cnf"
// openssl = C:\Users\Lee\source\GnuWin32\bin\openssl.exe

#[tokio::main]
async fn main() -> Result<()> {
    let args: Arguments = StructOpt::from_args();
    if args.clean {
        let _ = fs::remove_dir_all(&args.output).await;
    }

    let config = Config::read_config(&args.config).await?;
    let file_manager = FileManager::new(&args.output, args.verbose).await?;
    let cert_manager = CertManager::new(&config, &file_manager, args.openssl_path.as_deref());
    let hub_manager = IoTHubDeviceManager::new(&config, &file_manager, &cert_manager);
    let device_config_manager = DeviceConfigManager::new(&config, &file_manager);
    let script_manager = ScriptManager::new(&config, &file_manager);

    file_manager
        .print_verbose(format!("Using options:\n{:#?}", args))
        .await?;

    config.check_device_ids().await?;
    config.check_hostnames(&file_manager).await?;

    visualize_terminal(&config.root_device, &file_manager).await?;
    if args.visualize {
        return Ok(());
    }

    if args.delete || args.force {
        hub_manager.delete_devices().await?;

        if args.delete {
            return Ok(());
        }
    }

    cert_manager.make_all_device_ca_certs().await?;
    let created_devices = hub_manager.create_devices().await?;

    device_config_manager
        .make_all_device_configs(&created_devices)
        .await?;

    script_manager.add_install_scripts(&created_devices).await?;

    fs::write(
        file_manager.base_path().join("README.md"),
        include_str!(r#"docs/root_readme.md"#),
    )
    .await?;

    if args.zip_options != ZipOptions::None {
        file_manager
            .print_verbose("Zipping all device folders.")
            .await?;
        for device in created_devices {
            file_manager
                .zip_dir(file_manager.get_folder(&device.device.device_id).await?)
                .await?
        }

        if args.zip_options == ZipOptions::All {
            file_manager.print_verbose("Zipping output folder.").await?;
            file_manager.zip_dir(file_manager.base_path()).await?;
        }
    }

    let output = if args.zip_options == ZipOptions::All {
        FileManager::path_to_zip(file_manager.base_path())
    } else {
        file_manager.base_path().to_path_buf()
    };
    let output = std::fs::canonicalize(&output).unwrap_or(output);
    file_manager
        .print(format!(
            "Done! Output located at {:?}. See README.md in output for install instructions.",
            output
        ))
        .await?;

    Ok(())
}

#[derive(StructOpt, Debug)]
struct Arguments {
    /// Verbose: gives more detailed output
    #[structopt(short, long)]
    verbose: bool,

    /// Delete: deletes devices in hub instead of creating them
    #[structopt(short, long)]
    delete: bool,

    /// Force: tries to delete devices in hub before creating new ones
    #[structopt(short, long)]
    force: bool,

    /// Clean: deletes working directory at start
    #[structopt(long)]
    clean: bool,

    /// Visualize: only outputs visualization file, does no other work
    #[structopt(long)]
    visualize: bool,

    /// Output: path to create directory at.
    #[structopt(short, long, default_value = "./iotedge_config_cli")]
    output: PathBuf,

    /// Config: path to config file.
    #[structopt(short, long, default_value = "./iotedge_config_cli.yaml")]
    config: PathBuf,

    /// Openssl Path: Path to openssl executable. Only needed if `openssl` is not in PATH.
    #[structopt(long)]
    openssl_path: Option<PathBuf>,

    /// Zip Options: what should be zipped: all, devices, or none.
    #[structopt(long, default_value = "devices")]
    zip_options: ZipOptions,
}

#[derive(StructOpt, Debug, PartialEq)]
enum ZipOptions {
    None,
    Devices,
    All,
}

impl std::str::FromStr for ZipOptions {
    type Err = anyhow::Error;
    fn from_str(string: &str) -> Result<Self> {
        let result = match string.to_lowercase().as_str() {
            "all" => Self::All,
            "devices" => Self::Devices,
            "none" => Self::None,
            _ => {
                return Err(anyhow::Error::msg(format!(
                    "Did not recognize zip argument: {}",
                    string
                )))
            }
        };

        Ok(result)
    }
}

impl Config {
    pub async fn read_config<P>(file_path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        println!("Reading {:?}", file_path.as_ref());
        let data = fs::read(file_path).await.context("Error reading file")?;

        let version: ConfigVersion =
            serde_yaml::from_slice(&data).context("Error parsing config version")?;
        match version.config_version.as_str() {
            "1.0" => (),
            _ => {
                return Err(anyhow::Error::msg(
                    "Invalid api_version. Accepted values are: 1.0",
                ))
            }
        }

        serde_yaml::from_slice(&data).context("Error parsing data")
    }

    async fn check_device_ids(&self) -> Result<()> {
        let devices = FlatenedDevice::flatten_devices(&self.root_device);
        let mut map = HashSet::new();

        for device in devices {
            if !map.insert(&device.device.device_id) {
                let error = format!(r#"device id "{}" is used twice!"#, device.device.device_id);

                return Err(anyhow::Error::msg(error));
            }
        }

        Ok(())
    }

    async fn check_hostnames(&self, file_manager: &FileManager) -> Result<()> {
        let devices = FlatenedDevice::flatten_devices(&self.root_device);
        let mut map = HashMap::new();

        for device in devices {
            if let Some(hostname) = &device.device.hostname {
                if let Some(old) = map.insert(hostname, &device.device.device_id) {
                    file_manager
                        .print(format!(
                            "\n\nWARNING: {} and {} share the hostname {}\n\n",
                            old, device.device.device_id, hostname
                        ))
                        .await?;
                }
            }
        }

        Ok(())
    }
}

struct FlatenedDevice<'a> {
    device: &'a DeviceConfig,
    parent: Option<&'a DeviceConfig>,
}

impl<'a> FlatenedDevice<'a> {
    pub fn flatten_devices(root: &'a DeviceConfig) -> Vec<Self> {
        Self::flatten_devices_internal(root, None)
    }

    fn flatten_devices_internal(
        device: &'a DeviceConfig,
        parent: Option<&'a DeviceConfig>,
    ) -> Vec<Self> {
        let mut result: Vec<FlatenedDevice> = vec![FlatenedDevice { device, parent }];
        for child in &device.children {
            result.append(&mut Self::flatten_devices_internal(&child, Some(device)));
        }

        result
    }
}

struct CreatedDevice<'a> {
    device: &'a DeviceConfig,
    parent: Option<&'a DeviceConfig>,
    create_response: CreateResponse,
}

struct IoTHubDeviceManager<'a> {
    config: &'a Config,
    file_manager: &'a FileManager,
    cert_manager: &'a CertManager<'a>,
}

impl<'a> IoTHubDeviceManager<'a> {
    pub fn new(
        config: &'a Config,
        file_manager: &'a FileManager,
        cert_manager: &'a CertManager,
    ) -> Self {
        Self {
            config,
            file_manager,
            cert_manager,
        }
    }

    pub async fn create_devices(&self) -> Result<Vec<CreatedDevice<'_>>> {
        // Create devices
        let devices_to_create = FlatenedDevice::flatten_devices(&self.config.root_device);
        self.file_manager
            .print(&format!(
                "Creating {} devices in hub {}",
                devices_to_create.len(),
                self.config.iothub.iothub_name
            ))
            .await?;

        let futures = devices_to_create
            .iter()
            .map(|d| self.create_device_identity(d));

        let created_devices = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<CreatedDevice<'_>>>>()?;

        // Add parent-child relationships
        let relationships_to_add = created_devices.iter().filter_map(|child| {
            child
                .parent
                .map(|parent| (&parent.device_id, &child.device.device_id))
        });
        self.file_manager
            .print_verbose("Adding parent-child relationships.")
            .await?;

        let futures = relationships_to_add
            .map(|(parent, child)| self.create_parent_child_relationship(parent, child));

        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<()>>>()?;
        self.file_manager
            .print_verbose("Created all relationships.")
            .await?;

        Ok(created_devices)
    }

    pub async fn delete_devices(&self) -> Result<()> {
        let devices_to_delete = FlatenedDevice::flatten_devices(&self.config.root_device);
        self.file_manager
            .print(&format!(
                "Deleting {} devices from hub {}",
                devices_to_delete.len(),
                self.config.iothub.iothub_name
            ))
            .await?;

        let futures = devices_to_delete
            .iter()
            .map(|d| self.delete_device_identity(&d.device.device_id));

        let num_successes = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<bool>>>()?
            .into_iter()
            .filter(|s| *s)
            .count();

        if num_successes == devices_to_delete.len() {
            self.file_manager
                .print_verbose("Deleted all devices.")
                .await?;
        } else {
            self.file_manager
                .print(&format!(
                "Successfully deleted {} devices, {} failed. For more information use the -v flag.",
                num_successes,
                num_successes - devices_to_delete.len(),
            ))
                .await?;
        }

        Ok(())
    }

    async fn create_device_identity<'b>(
        &self,
        device: &FlatenedDevice<'b>,
    ) -> Result<CreatedDevice<'b>> {
        self.file_manager
            .print_verbose(format!(
                "Creating device {} on hub {}",
                device.device.device_id, self.config.iothub.iothub_name
            ))
            .await?;

        let mut args = vec![
            "az iot hub device-identity create",
            "--device-id",
            &device.device.device_id,
            "--hub-name",
            &self.config.iothub.iothub_name,
            "--edge-enabled",
        ];

        let primary_thumbprint: String;
        let secondary_thumbprint: String;
        if self.config.iothub.authentication_method == IoTHubAuthMethod::X509Cert {
            let auth_cert = self
                .cert_manager
                .make_hub_auth_cert(&device.device.device_id)
                .await?;

            primary_thumbprint = self.cert_manager.get_thumbprint(&auth_cert).await?;
            secondary_thumbprint = self
                .cert_manager
                .get_thumbprint(
                    &self
                        .cert_manager
                        .device_ca_path(&device.device.device_id)
                        .await?,
                )
                .await?;

            args.extend(&["--auth-method", "x509_thumbprint"]);
            args.extend(&["--primary-thumbprint", &primary_thumbprint]);
            args.extend(&["--secondary-thumbprint", &secondary_thumbprint]);
        }

        let command = run_command(&args).output().await?;
        if command.status.success() {
            self.file_manager
                .print_verbose(format!(
                    "Successfully created {}.\n{}",
                    device.device.device_id,
                    String::from_utf8_lossy(&command.stdout)
                ))
                .await?;

            let created_device: CreateResponse = serde_json::from_slice(&command.stdout)?;

            if let Some(deployment) = &device.device.deployment {
                self.set_deployment(&device.device.device_id, &deployment)
                    .await?;
            }
            Ok(CreatedDevice {
                device: device.device,
                parent: device.parent,
                create_response: created_device,
            })
        } else {
            let error = format!(
                "Failed to create {}:\n{}\n{}\nMake sure you are running as sudo and try using the -f flag to delete existing devices before creation.",
                device.device.device_id,
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            );
            self.file_manager.print_verbose(&error).await?;

            Err(anyhow::Error::msg(error))
        }
    }

    async fn create_parent_child_relationship(&self, parent: &str, child: &str) -> Result<()> {
        self.file_manager
            .print_verbose(format!("Adding {} as child of parent {}.", child, parent,))
            .await?;

        let args = &[
            "az iot hub device-identity parent set",
            "--device-id",
            child,
            "--parent-device-id",
            parent,
            "--hub-name",
            &self.config.iothub.iothub_name,
        ];
        let command = run_command(args).output().await?;
        if command.status.success() {
            self.file_manager
                .print_verbose(format!(
                    "Successfully added {} as child of parent {}.\n{}",
                    child,
                    parent,
                    String::from_utf8_lossy(&command.stdout)
                ))
                .await?;

            Ok(())
        } else {
            let error = format!(
                "Failed to add {} as child of parent {}:\n{}\n{}\n",
                child,
                parent,
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            );
            self.file_manager.print_verbose(&error).await?;

            Err(anyhow::Error::msg(error))
        }
    }

    async fn delete_device_identity(&self, device_id: &str) -> Result<bool> {
        self.file_manager
            .print_verbose(format!(
                "Deleting device {} on hub {}",
                device_id, self.config.iothub.iothub_name
            ))
            .await?;

        let args = &[
            "az iot hub device-identity delete",
            "--device-id",
            device_id,
            "--hub-name",
            &self.config.iothub.iothub_name,
        ];

        let command = run_command(args)
            // .spawn()?;
            .output()
            .await?;

        if command.status.success()
            || String::from_utf8_lossy(&command.stderr).contains("ErrorCode:DeviceNotFound;")
        {
            self.file_manager
                .print_verbose(format!(
                    "Successfully deleted {}.\n{}",
                    device_id,
                    String::from_utf8_lossy(&command.stdout)
                ))
                .await?;
            Ok(true)
        } else {
            self.file_manager
                .print_verbose(format!(
                    "Failed to delete {}:\n{}\n{}\n",
                    device_id,
                    String::from_utf8_lossy(&command.stdout),
                    String::from_utf8_lossy(&command.stderr)
                ))
                .await?;

            Ok(false)
        }
    }

    async fn set_deployment(&self, device_id: &str, path: &str) -> Result<()> {
        self.file_manager
            .print_verbose(format!("Setting {}'s deployment to {}", device_id, path))
            .await?;

        let args = &[
            "az iot edge set-modules",
            "--device-id",
            device_id,
            "--hub-name",
            &self.config.iothub.iothub_name,
            "--content",
            path,
        ];
        let command = run_command(args).output().await?;
        if command.status.success() {
            self.file_manager
                .print_verbose(format!(
                    "Successfully set deployment for {}.\n{}",
                    device_id,
                    String::from_utf8_lossy(&command.stdout)
                ))
                .await?;

            Ok(())
        } else {
            let error = format!(
                "Failed to set deployment for {}:\n{}\n{}\n",
                device_id,
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            );
            self.file_manager.print_verbose(&error).await?;

            Err(anyhow::Error::msg(error))
        }
    }
}

struct CertManager<'a> {
    config: &'a Config,
    file_manager: &'a FileManager,
    openssl_path: Option<&'a Path>,
}

impl<'a> CertManager<'a> {
    pub fn new(
        config: &'a Config,
        file_manager: &'a FileManager,
        openssl_path: Option<&'a Path>,
    ) -> Self {
        Self {
            config,
            file_manager,
            openssl_path,
        }
    }

    pub async fn device_ca_path(&self, device_id: &str) -> Result<PathBuf> {
        let path = self
            .file_manager
            .get_folder(device_id)
            .await?
            .join(format!("{}.full-chain.cert.pem", device_id));

        Ok(path)
    }

    pub async fn make_all_device_ca_certs(&self) -> Result<()> {
        let device_ids: Vec<&str> = FlatenedDevice::flatten_devices(&self.config.root_device)
            .iter()
            .map(|d| d.device.device_id.as_str())
            .collect();

        let (cert_path, key_path) = if let Some(certificates) = &self.config.certificates {
            self.file_manager
                .print(format!(
                    "Using root CA {:?} with key {:?}.",
                    certificates.root_ca_cert_path, certificates.root_ca_cert_key_path
                ))
                .await?;

            (
                PathBuf::from_str(&certificates.root_ca_cert_path)?,
                PathBuf::from_str(&certificates.root_ca_cert_key_path)?,
            )
        } else {
            self.make_root_cert().await?
        };

        self.file_manager
            .print(format!(
                "Creating certificates for {} devices",
                device_ids.len(),
            ))
            .await?;

        let config = self
            .file_manager
            .get_folder("certificates")
            .await?
            .join("v3_ca_extensions.cnf");
        fs::write(config, include_str!(r#"scripts/v3_ca_extensions.cnf"#)).await?;

        let futures = device_ids
            .iter()
            .map(|d| self.make_device_ca_cert(d, &cert_path, &key_path));

        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<()>>>()?;

        self.file_manager
            .print_verbose("Created all device certs.")
            .await?;

        Ok(())
    }

    async fn make_root_cert(&self) -> Result<(PathBuf, PathBuf)> {
        let cert_folder = self.file_manager.get_folder("certificates").await?;
        let cert_path = cert_folder.join("iotedge_config_cli_root.pem");
        let key_path = cert_folder.join("iotedge_config_cli_root.key.pem");
        self.file_manager
            .print(format!(
                "No Root CA specified. Generating self-signed root at {:?}.",
                cert_path
            ))
            .await?;

        let command = self
            .openssl_command()
            .arg("req")
            .args(&[
                "-x509",
                "-new",
                "-newkey",
                "rsa:4096",
                "-days",
                "365",
                "-nodes",
                "-addext",
                "keyUsage=critical, digitalSignature, cRLSign, keyCertSign",
            ])
            .args(&[OsStr::new("-keyout"), key_path.as_os_str()])
            .args(&[OsStr::new("-out"), cert_path.as_os_str()])
            .args(&["-subj", "/CN=Azure_IoT_Config_Cli_Cert"])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        Ok((cert_path, key_path))
    }

    async fn make_device_ca_cert(
        &self,
        device_id: &str,
        ca_cert_path: &Path,
        ca_key_path: &Path,
    ) -> Result<()> {
        let device_folder = self.file_manager.get_folder(device_id).await?;
        let csr = device_folder.join("device-id.csr");
        let device_key = device_folder.join(format!("{}.key.pem", device_id));
        let device_cert = device_folder.join(format!("{}.cert.pem", device_id));
        let config = self
            .file_manager
            .get_folder("certificates")
            .await?
            .join("v3_ca_extensions.cnf");

        // CSR
        self.file_manager
            .print_verbose(format!("Making device csr for {}.", device_id))
            .await?;
        let command = self
            .openssl_command()
            .arg("req")
            .args(&["-newkey", "rsa:4096", "-nodes"])
            .args(&[OsStr::new("-keyout"), device_key.as_os_str()])
            .args(&[OsStr::new("-out"), csr.as_os_str()])
            .args(&["-subj", &format!("/CN={}", device_id)])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        if !command.status.success() {
            return Err(anyhow::Error::msg(format!(
                "Error making csr for {}",
                device_id
            )));
        }

        // Sign Cert
        self.file_manager
            .print_verbose(format!(
                "Making device cert based on for {:?} using {:?}.",
                csr, ca_cert_path
            ))
            .await?;
        let command = self
            .openssl_command()
            .arg("x509")
            .args(&[
                "-req",
                "-days",
                "365",
                "-CAcreateserial",
                "-extensions",
                "v3_ca",
            ])
            .args(&[OsStr::new("-in"), csr.as_os_str()])
            .args(&[OsStr::new("-out"), device_cert.as_os_str()])
            .args(&[OsStr::new("-CA"), ca_cert_path.as_os_str()])
            .args(&[OsStr::new("-CAkey"), ca_key_path.as_os_str()])
            .args(&[OsStr::new("-extfile"), config.as_os_str()])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        if !command.status.success() {
            return Err(anyhow::Error::msg(format!(
                "Error making cert for {}",
                device_id
            )));
        }

        self.file_manager
            .print_verbose(format!(
                "Successfully made cert {:?}. Copying root cert to folder.",
                device_cert
            ))
            .await?;

        fs::remove_file(csr).await?;
        fs::copy(
            ca_cert_path,
            device_folder.join(ca_cert_path.file_name().unwrap()),
        )
        .await?;

        self.file_manager
            .print_verbose("Copied Root. Making cert chain.")
            .await?;

        Self::make_cert_chain(
            &[&device_cert, ca_cert_path],
            &self.device_ca_path(device_id).await?,
        )
        .await?;

        Ok(())
    }

    pub async fn make_hub_auth_cert(&self, device_id: &str) -> Result<PathBuf> {
        let device_folder = self.file_manager.get_folder(device_id).await?;
        let device_cert = device_folder.join(format!("{}.hub-auth.cert.pem", device_id));
        let device_key = device_folder.join(format!("{}.hub-auth.key.pem", device_id));
        self.file_manager
            .print_verbose(format!(
                "Generating self-signed hub cert for {} at {:?}.",
                device_id, device_cert
            ))
            .await?;

        let command = self
            .openssl_command()
            .arg("req")
            .args(&[
                "-x509", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            ])
            .args(&[OsStr::new("-keyout"), device_key.as_os_str()])
            .args(&[OsStr::new("-out"), device_cert.as_os_str()])
            .args(&["-subj", &format!("/CN={}", device_id)])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        Ok(device_cert)
    }

    pub async fn get_thumbprint(&self, cert: &Path) -> Result<String> {
        self.file_manager
            .print_verbose(format!("Getting thumbprint for {:?}", cert))
            .await?;

        let command = self
            .openssl_command()
            .args(&["x509", "--noout", "-fingerprint"])
            .args(&[OsStr::new("-in"), cert.as_os_str()])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        if !command.status.success() {
            return Err(anyhow::Error::msg(format!(
                "Error getting fingerprint for {:?}",
                cert
            )));
        }

        let thumbprint = String::from_utf8_lossy(&command.stdout);
        let mut thumbprint = thumbprint
            .split('=')
            .into_iter()
            .nth(1)
            .unwrap_or_else(|| {
                panic!(
                    "Unable to parse openssl fingerprint response:\n{}",
                    String::from_utf8_lossy(&command.stdout)
                )
            })
            .trim()
            .to_owned();
        thumbprint.retain(|c| c != ':');

        Ok(thumbprint)
    }

    async fn make_cert_chain(certs: &[&Path], out: &Path) -> Result<()> {
        let mut file = fs::File::create(out).await?;
        for cert in certs {
            file.write_all(&fs::read(cert).await?).await?;
        }

        Ok(())
    }

    fn openssl_command(&self) -> Command {
        self.openssl_path
            .map_or_else(|| Command::new("openssl"), Command::new)
    }
}

struct DeviceConfigManager<'a> {
    config: &'a Config,
    file_manager: &'a FileManager,
}

impl<'a> DeviceConfigManager<'a> {
    pub fn new(config: &'a Config, file_manager: &'a FileManager) -> Self {
        Self {
            config,
            file_manager,
        }
    }

    pub async fn make_all_device_configs(&self, devices: &[CreatedDevice<'_>]) -> Result<()> {
        self.file_manager
            .print(&format!(
                "Creating configuration files based on {:?} for {} devices.",
                self.config.configuration.template_config_path,
                devices.len(),
            ))
            .await?;

        let base_config = fs::read(&self.config.configuration.template_config_path).await?;
        let base_config = String::from_utf8(base_config)?;

        self.file_manager
            .print_verbose(format!("Base Config File: {:#?}", base_config))
            .await?;

        for device in devices {
            self.make_device_config(&device, &base_config).await?;
        }

        self.file_manager
            .print_verbose("Created config files.")
            .await?;

        Ok(())
    }

    async fn make_device_config(
        &self,
        device: &CreatedDevice<'_>,
        base_config: &str,
    ) -> Result<()> {
        self.file_manager
            .print_verbose(format!("Generating config for {}", device.device.device_id))
            .await?;

        let authentication = match self.config.iothub.authentication_method {
            IoTHubAuthMethod::SymmetricKey => aziot_config::ManualAuthMethod::SharedPrivateKey {
                device_id_pk: aziot_config::DeviceIdPk {
                    value: device
                        .create_response
                        .authentication
                        .symmetric_key
                        .primary_key
                        .clone()
                        .ok_or_else(|| {
                            anyhow::Error::msg("Hub response did not contain symmetric key")
                        })?,
                },
            },
            IoTHubAuthMethod::X509Cert => aziot_config::ManualAuthMethod::X509 {
                identity: aziot_config::X509Identity {
                    identity_cert: format!(
                        "file:///etc/aziot/certificates/{}.hub-auth.cert.pem",
                        device.device.device_id
                    ),
                    identity_pk: format!(
                        "file:///etc/aziot/certificates/{}.hub-auth.key.pem",
                        device.device.device_id
                    ),
                },
            },
        };

        let provisioning = aziot_config::Provisioning {
            source: "manual".to_owned(),
            device_id: device.device.device_id.clone(),
            iothub_hostname: self.config.iothub.iothub_hostname.clone(),
            authentication,
        };

        let hostname = device
            .device
            .hostname
            .as_deref()
            .unwrap_or("{{HOSTNAME}}")
            .to_owned();

        let parent_hostname = device.parent.map(|p| {
            p.hostname
                .as_deref()
                .unwrap_or("{{PARENT_HOSTNAME}}")
                .to_owned()
        });

        let trust_bundle_cert =
            "file:///etc/aziot/certificates/iotedge_config_cli_root.pem".to_owned();

        let edge_ca = aziot_config::EdgeCa {
            cert: format!(
                "file:///etc/aziot/certificates/{}.full-chain.cert.pem",
                device.device.device_id
            ),
            pk: format!(
                "file:///etc/aziot/certificates/{}.key.pem",
                device.device.device_id
            ),
        };

        let image = device
            .device
            .edge_agent
            .as_ref()
            .unwrap_or(&self.config.configuration.default_edge_agent);
        let agent = aziot_config::Agent {
            config: aziot_config::AgentConfig {
                image: image.to_owned(),
            },
        };

        let config = aziot_config::AziotConfig {
            provisioning,
            hostname,
            parent_hostname,
            trust_bundle_cert,
            edge_ca,
            agent,
        };

        let config = toml::to_string(&config)?;
        let config = &[&config, base_config].join("\n\n");

        let file = self
            .file_manager
            .get_folder(&device.device.device_id)
            .await?
            .join("config.toml");
        self.file_manager
            .print_verbose(format!(
                "Writing config for {} to {:?}\n{}",
                device.device.device_id, file, config
            ))
            .await?;

        fs::write(file, config).await?;
        Ok(())
    }
}

use std::io::prelude::*;
use std::io::{Seek, Write};
use std::iter::Iterator;
use std::path::{Path, PathBuf};

use walkdir::{DirEntry, WalkDir};
use zip::write::FileOptions;

struct FileManager {
    base_path: PathBuf,
    log_file: Arc<Mutex<fs::File>>,
    verbose: bool,
}

impl FileManager {
    async fn new<P>(base_path: P, verbose: bool) -> Result<Self>
    where
        P: Into<PathBuf>,
    {
        let base_path: PathBuf = base_path.into();
        fs::create_dir_all(&base_path).await?;

        let time = Local::now().format("%Y-%m-%d_%H-%M-%S");
        let log_file = base_path.join(format!("log_{}.txt", time));
        let message = format!("Writing logs to {:?}", log_file);
        let log_file = fs::File::create(log_file).await?;
        let log_file = Arc::new(Mutex::new(log_file));

        let this = Self {
            base_path,
            log_file,
            verbose,
        };
        this.print(message).await?;
        Ok(this)
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    pub async fn get_folder(&self, path: &str) -> Result<PathBuf> {
        let mut folder = self.base_path.clone();
        folder.push(path);

        fs::create_dir_all(&folder).await?;

        Ok(folder)
    }

    pub fn path_to_zip<P>(path: P) -> PathBuf
    where
        P: AsRef<Path>,
    {
        let mut output = path.as_ref().to_path_buf();
        output.set_file_name(&format!(
            "{}.zip",
            output.file_name().unwrap().to_string_lossy()
        ));

        output
    }

    // from https://github.com/zip-rs/zip/blob/5290d687b287a444f61bba32605423f01fd5b1c3/examples/write_dir.rs
    pub async fn zip_dir<P>(&self, dir: P) -> Result<()>
    where
        P: AsRef<Path> + Clone,
    {
        let dest = Self::path_to_zip(&dir);
        self.print_verbose(format!("Zipping {:?} into {:?}", dir.as_ref(), dest))
            .await?;

        // Note zipping is done synchronously since the zip lib is sync
        let file = std::fs::File::create(&dest)?;

        let walkdir = WalkDir::new(dir.clone());
        let it = walkdir.into_iter();

        self.zip_dir_inner(&mut it.filter_map(|e| e.ok()), &dir, file)?;
        fs::remove_dir_all(dir).await?;

        Ok(())
    }

    fn zip_dir_inner<T, P>(
        &self,
        it: &mut dyn Iterator<Item = DirEntry>,
        prefix: P,
        writer: T,
    ) -> zip::result::ZipResult<()>
    where
        T: Write + Seek,
        P: AsRef<Path> + Clone,
    {
        let mut zip = zip::ZipWriter::new(writer);
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);

        let mut buffer = Vec::new();
        for entry in it {
            let path = entry.path();
            let name = path.strip_prefix(prefix.clone()).unwrap();

            // Write file or directory explicitly
            // Some unzip tools unzip files with directory paths correctly, some do not!
            if path.is_file() {
                #[allow(deprecated)]
                zip.start_file_from_path(name, options)?;
                let mut f = std::fs::File::open(path)?;

                f.read_to_end(&mut buffer)?;
                zip.write_all(&*buffer)?;
                buffer.clear();
            } else if !name.as_os_str().is_empty() {
                // Only if not root! Avoids path spec / warning
                // and mapname conversion failed error on unzip
                #[allow(deprecated)]
                zip.add_directory_from_path(name, options)?;
            }
        }
        zip.finish()?;
        Result::Ok(())
    }

    async fn print<S>(&self, text: S) -> Result<()>
    where
        S: AsRef<str>,
    {
        println!("{}", text.as_ref());

        self.write_log(&format!(
            "{} {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            text.as_ref()
        ))
        .await?;
        Ok(())
    }

    async fn print_verbose<S>(&self, text: S) -> Result<()>
    where
        S: AsRef<str>,
    {
        if self.verbose {
            println!("{}", text.as_ref());
        }

        self.write_log(&format!(
            "{} {}\n",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            text.as_ref()
        ))
        .await?;
        Ok(())
    }

    async fn write_log(&self, text: &str) -> Result<()> {
        let log_file = self.log_file.clone();
        let mut log_file = log_file.lock().await;
        log_file.write_all(text.as_bytes()).await?;
        Ok(())
    }
}

struct ScriptManager<'a> {
    config: &'a Config,
    file_manager: &'a FileManager,
}

impl<'a> ScriptManager<'a> {
    pub fn new(config: &'a Config, file_manager: &'a FileManager) -> Self {
        Self {
            config,
            file_manager,
        }
    }

    pub async fn add_install_scripts(&self, devices: &[CreatedDevice<'_>]) -> Result<()> {
        self.file_manager
            .print_verbose("Adding install scripts for all devices")
            .await?;

        for device in devices {
            self.add_install_scripts_internal(&device).await?;
            self.copy_device_readme(device).await?;
        }

        Ok(())
    }

    async fn add_install_scripts_internal(&self, device: &CreatedDevice<'_>) -> Result<()> {
        let hostname = device.device.hostname.as_deref();
        let parent_hostname = device.parent.and_then(|p| p.hostname.as_deref());
        self.file_manager
            .print_verbose(format!(
                "Adding install script for {} with hostname {:?} and parent hostname {:?}. (If values are none, install script will prompt user for values).",
                device.device.device_id,
                hostname,
                parent_hostname
            ))
            .await?;

        let mut script: Vec<&str> = Vec::new();
        let headers = format!(
            include_str!(r#"scripts/headers.sh"#),
            device_id = device.device.device_id
        );
        script.push(&headers);

        // Add user prompts if no hostname provided
        if hostname.is_none() {
            script.push(include_str!(r#"scripts/set_hostname.sh"#));
        }
        if device.parent.is_some() && parent_hostname.is_none() {
            script.push(include_str!(r#"scripts/set_parent_hostname.sh"#));
        }

        // Copy certs to /aziot/certificates folder
        script.push(include_str!(r#"scripts/install_ca_certs.sh"#));
        if self.config.iothub.authentication_method == IoTHubAuthMethod::X509Cert {
            script.push(include_str!(r#"scripts/install_hub_auth_certs.sh"#));
        }

        // Run iotedge config apply
        script.push(include_str!(r#"scripts/apply.sh"#));

        let script: String = script.join("\n\n");
        let file = self
            .file_manager
            .get_folder(&device.device.device_id)
            .await?
            .join("install.sh");
        fs::write(file, script).await?;

        Ok(())
    }

    async fn copy_device_readme(&self, device: &CreatedDevice<'_>) -> Result<()> {
        let file = self
            .file_manager
            .get_folder(&device.device.device_id)
            .await?
            .join("README.md");
        fs::write(file, include_str!(r#"docs/device_readme.md"#)).await?;

        Ok(())
    }
}

async fn visualize_terminal(root: &DeviceConfig, file_manager: &FileManager) -> Result<()> {
    let result = make_tree(root, "")?;
    file_manager.print(&result).await?;
    fs::write(file_manager.base_path().join("visualization.txt"), result).await?;

    Ok(())
}

fn make_tree(device: &DeviceConfig, prefix: &str) -> Result<String> {
    let mut result: Vec<String> = vec![device.device_id.clone(), "\n".to_owned()];

    let num_children = device.children.len();
    for (i, child) in device.children.iter().enumerate() {
        let is_last = i + 1 == num_children;
        let node_prefix = if is_last { "└──" } else { "├──" };
        let node_prefix = [prefix, node_prefix].concat();
        result.push(node_prefix);

        let child_prefix = if is_last { "    " } else { "│   " };
        let child_prefix = [prefix, child_prefix].concat();
        result.push(make_tree(&child, &child_prefix)?);
    }

    Ok(result.concat())
}

fn run_command(args: &[&str]) -> Command {
    #[cfg(any(unix))]
    {
        let args = args.join(" ");
        let mut command = Command::new("sh");
        command.arg("-c").arg(args);
        command
    }

    #[cfg(any(windows))]
    {
        let mut command = Command::new("powershell.exe");
        command.args(args);
        command
    }
}
