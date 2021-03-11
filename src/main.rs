use std::ffi::OsStr;
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
    let args_log = format!("Using options:\n{:#?}", args);

    let config = read_config(args.config).await?;
    let file_manager = FileManager::new(args.output, args.verbose).await?;
    let hub_manager = IoTHubDeviceManager::new(&config, &file_manager);
    let cert_manager = CertManager::new(&config, &file_manager, args.openssl_path.as_deref());
    let config_manager = DeviceConfigManager::new(&config, &file_manager);

    file_manager.print_verbose(args_log).await?;

    visualize(&config.root_device, &file_manager).await?;
    if args.visualize {
        return Ok(());
    }

    if args.delete || args.force {
        hub_manager.delete_devices().await?;

        if args.delete {
            return Ok(());
        }
    }

    let created_devices = hub_manager.create_devices().await?;
    if args.create {
        return Ok(());
    }
    let device_ids: Vec<&str> = created_devices
        .iter()
        .map(|d| d.device_id.as_str())
        .collect();

    cert_manager.make_root_cert().await?;
    cert_manager.make_all_device_certs(&device_ids).await?;

    config_manager
        .make_all_device_configs(&created_devices)
        .await?;

    if args.zip_options != ZipOptions::None {
        file_manager.print("Zipping all device folders.").await?;
        for device in device_ids {
            file_manager
                .zip_dir(file_manager.get_folder(device).await?)
                .await?
        }

        if args.zip_options == ZipOptions::All {
            file_manager.print("Zipping output folder.").await?;
            file_manager.zip_dir(file_manager.base_path()).await?;
        }
    }

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

    /// Create: Only creates devices in ioh hub, does not make certs or configs
    #[structopt(long)]
    create: bool,

    /// Force: tries to delete devices in hub before creating new ones
    #[structopt(short, long)]
    force: bool,

    /// Visualize: only outputs visualization file, does no other work
    #[structopt(long)]
    visualize: bool,

    /// Output: path to create directory at.
    #[structopt(short, long, default_value = "./nested")]
    output: PathBuf,

    /// Config: path to config file.
    #[structopt(short, long, default_value = "./nested_config.yaml")]
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

async fn read_config(file_path: PathBuf) -> Result<Config> {
    println!("Reading {:?}", file_path);
    let is_toml = file_path.to_str().unwrap().ends_with(".toml");

    let data = fs::read(file_path).await.context("Error reading file")?;

    let config = if is_toml {
        toml::from_slice(&data).context("Error parsing data")?
    } else {
        serde_yaml::from_slice(&data).context("Error parsing data")?
    };

    Ok(config)
}

fn flatten_devices(device: &DeviceConfig) -> Vec<&str> {
    let mut result: Vec<&str> = vec![&device.device_id];
    for child in &device.children {
        result.append(&mut flatten_devices(&child));
    }

    result
}

struct IoTHubDeviceManager<'a> {
    config: &'a Config,
    file_manager: &'a FileManager,
}

impl<'a> IoTHubDeviceManager<'a> {
    pub fn new(config: &'a Config, file_manager: &'a FileManager) -> Self {
        Self {
            config,
            file_manager,
        }
    }

    pub async fn create_devices(&self) -> Result<Vec<CreateResponse>> {
        // Create devices
        let devices_to_create = flatten_devices(&self.config.root_device);
        self.file_manager
            .print(&format!(
                "Creating {} devices in hub {}",
                devices_to_create.len(),
                self.config.iothub.iot_hub_name
            ))
            .await?;

        let futures = devices_to_create
            .iter()
            .map(|d| self.create_device_identity(d));

        let created_devices = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<CreateResponse>>>()?;
        // Add parent-child relationships
        let relationships_to_add = Self::get_relationships(&self.config.root_device);
        self.file_manager
            .print(&format!(
                "Created all devices. Adding {} parent-child relationships.",
                relationships_to_add.len()
            ))
            .await?;

        let futures = relationships_to_add
            .iter()
            .map(|(parent, child)| self.create_parent_child_relationship(parent, child));

        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<()>>>()?;
        self.file_manager
            .print("Created all relationships.")
            .await?;

        Ok(created_devices)
    }

    pub async fn delete_devices(&self) -> Result<()> {
        let devices_to_delete = flatten_devices(&self.config.root_device);
        self.file_manager
            .print(&format!(
                "Deleting {} devices from hub {}",
                devices_to_delete.len(),
                self.config.iothub.iot_hub_name
            ))
            .await?;

        let futures = devices_to_delete
            .iter()
            .map(|d| self.delete_device_identity(d));

        let num_successes = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<bool>>>()?
            .into_iter()
            .filter(|s| *s)
            .count();

        if num_successes == devices_to_delete.len() {
            self.file_manager.print("Deleted all devices.").await?;
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

    fn get_relationships(device: &DeviceConfig) -> Vec<(&str, &str)> {
        let mut result: Vec<(&str, &str)> = Vec::new();
        for child in &device.children {
            result.push((&device.device_id, &child.device_id));
            result.append(&mut Self::get_relationships(&child));
        }

        result
    }

    async fn create_device_identity(&self, device_id: &str) -> Result<CreateResponse> {
        self.file_manager
            .print_verbose(format!(
                "Creating device {} on hub {}",
                device_id, self.config.iothub.iot_hub_name
            ))
            .await?;

        let args = &[
            "az iot hub device-identity create",
            "--device-id",
            device_id,
            "--hub-name",
            &self.config.iothub.iot_hub_name,
            "--edge-enabled",
        ];
        let command = Self::run_az_command(args).output().await?;
        if command.status.success() {
            self.file_manager
                .print_verbose(format!("Successfully created {}", device_id))
                .await?;

            let created_device: CreateResponse = serde_json::from_slice(&command.stdout)?;
            Ok(created_device)
        } else {
            let error = format!(
                "Failed to create {}:\n{}\n{}\n",
                device_id,
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
            &self.config.iothub.iot_hub_name,
        ];
        let command = Self::run_az_command(args).output().await?;
        if command.status.success() {
            self.file_manager
                .print_verbose(format!(
                    "Successfully added {} as child of parent {}.",
                    child, parent,
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
                device_id, self.config.iothub.iot_hub_name
            ))
            .await?;

        let args = &[
            "az iot hub device-identity delete",
            "--device-id",
            device_id,
            "--hub-name",
            &self.config.iothub.iot_hub_name,
        ];

        let command = Self::run_az_command(args)
            // .spawn()?;
            .output()
            .await?;

        if command.status.success()
            || String::from_utf8_lossy(&command.stderr).contains("ErrorCode:DeviceNotFound;")
        {
            self.file_manager
                .print_verbose(format!("Successfully deleted {}", device_id))
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

    fn run_az_command(args: &[&str]) -> Command {
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

    pub async fn make_all_device_certs(&self, device_ids: &[&str]) -> Result<()> {
        self.file_manager
            .print(&format!("Creating certs for {} devices", device_ids.len(),))
            .await?;

        let futures = device_ids.iter().map(|d| self.make_device_cert(d));

        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<()>>>()?;

        self.file_manager.print("Created all device certs.").await?;

        Ok(())
    }

    pub async fn make_root_cert(&self) -> Result<()> {
        self.file_manager.print("Making Root CA.").await?;
        let cert_folder = self.file_manager.get_folder("certs").await?;
        let command = self
            .openssl_path
            .map_or_else(|| Command::new("openssl"), Command::new)
            .arg("req")
            .args(&[
                "-x509", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            ])
            .args(&[
                OsStr::new("-keyout"),
                cert_folder.join("root.key.pem").as_os_str(),
            ])
            .args(&[OsStr::new("-out"), cert_folder.join("root.pem").as_os_str()])
            .args(&["-subj", "/CN=Azure_IoT_Nested_Cert"])
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        self.file_manager
            .print(format!(
                "Successfully made Root CA {:?}.",
                cert_folder.join("root.pem")
            ))
            .await?;

        Ok(())
    }

    async fn make_device_cert(&self, device_id: &str) -> Result<()> {
        self.file_manager
            .print_verbose(format!("Making device CA for {}.", device_id))
            .await?;

        // TODO: make cert correctly
        let device_folder = self.file_manager.get_folder(device_id).await?;
        let command = self
            .openssl_path
            .map_or_else(|| Command::new("openssl"), Command::new)
            .arg("req")
            .args(&[
                "-x509", "-new", "-newkey", "rsa:4096", "-days", "365", "-nodes",
            ])
            .args(&[
                OsStr::new("-keyout"),
                device_folder.join("key.pem").as_os_str(),
            ])
            .args(&[
                OsStr::new("-out"),
                device_folder.join("cert.pem").as_os_str(),
            ])
            .args(&["-subj", "/CN=Azure_IoT_Nested_Cert"])
            // .spawn()?;
            .output()
            .await?;

        self.file_manager
            .print_verbose(format!(
                "{}{}",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

        self.file_manager
            .print_verbose(format!(
                "Successfully made CA {:?}.",
                device_folder.join("cert.pem")
            ))
            .await?;

        Ok(())
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

    pub async fn make_all_device_configs(&self, devices: &[CreateResponse]) -> Result<()> {
        self.file_manager
            .print(&format!(
                "Creating configuration files based on {:?} for {} devices.",
                self.config.configuration.template_config_path,
                devices.len(),
            ))
            .await?;

        let base_config: aziot_config::AziotConfig =
            if let Some(p) = &self.config.configuration.template_config_path {
                let base_config = fs::read(p).await?;
                toml::from_slice(&base_config)?
            } else {
                Default::default()
            };

        self.file_manager
            .print_verbose(format!("Base Config File: {:#?}", base_config))
            .await?;

        for device in devices {
            self.make_device_config(&device, base_config.clone())
                .await?;
        }

        self.file_manager.print("Created config files.").await?;

        Ok(())
    }

    async fn make_device_config(
        &self,
        device: &CreateResponse,
        mut config: aziot_config::AziotConfig,
    ) -> Result<()> {
        let provisioning = aziot_config::Provisioning {
            source: "manual".to_owned(),
            device_id: device.device_id.clone(),
            iothub_hostname: self.config.iothub.iot_hub_name.clone(), //TODO: get hostname not name
            authentication: aziot_config::Authentication {
                method: "sas".to_owned(),
                device_id_pk: aziot_config::DeviceIdPk {
                    value: device.authentication.symmetric_key.primary_key.clone(),
                },
            },
        };
        config.provisioning = Some(provisioning);

        let file = self
            .file_manager
            .get_folder(&device.device_id)
            .await?
            .join("config.toml");
        let config = toml::to_string(&config)?;
        self.file_manager
            .print_verbose(format!(
                "Writing config for {} to {:?}\n{}",
                device.device_id, file, config
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

    async fn get_folder(&self, path: &str) -> Result<PathBuf> {
        let mut folder = self.base_path.clone();
        folder.push(path);

        fs::create_dir_all(&folder).await?;

        Ok(folder)
    }

    // from https://github.com/zip-rs/zip/blob/5290d687b287a444f61bba32605423f01fd5b1c3/examples/write_dir.rs
    async fn zip_dir<P>(&self, dir: P) -> Result<()>
    where
        P: AsRef<Path> + Clone,
    {
        let mut dest = dir.as_ref().to_path_buf();
        dest.set_file_name(&format!(
            "{}.zip",
            dest.file_name().unwrap().to_string_lossy()
        ));

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

use id_tree::InsertBehavior::{AsRoot, UnderNode};
use id_tree::{Node, NodeId, Tree, TreeBuilder};
use id_tree_layout::{Layouter, Visualize};

struct NodeData(String);

async fn visualize(root: &DeviceConfig, file_manager: &FileManager) -> Result<()> {
    let path = file_manager.base_path().join("visualization.svg");
    file_manager
        .print(format!("Outputing visualization to {:?}", path))
        .await?;

    let mut tree: Tree<NodeData> = TreeBuilder::new().build();

    let root_id: NodeId = tree.insert(Node::new(NodeData(root.device_id.clone())), AsRoot)?;
    add_children(&root.children, &root_id, &mut tree)?;

    Layouter::new(&tree)
        .with_file_path(&path)
        .write()
        .context("Cannot write visualization file.")?;

    Ok(())
}

fn add_children(
    children: &[DeviceConfig],
    parent: &NodeId,
    tree: &mut Tree<NodeData>,
) -> Result<()> {
    for child in children {
        let new_node: NodeId = tree.insert(
            Node::new(NodeData(child.device_id.clone())),
            UnderNode(parent),
        )?;
        add_children(&child.children, &new_node, tree)?;
    }

    Ok(())
}

impl Visualize for NodeData {
    fn visualize(&self) -> std::string::String {
        // We simply convert the i32 value to string here.
        self.0.clone()
    }
    fn emphasize(&self) -> bool {
        false
    }
}
