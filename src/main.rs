use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::Mutex;

use anyhow::{Context, Result};
use futures::future::{BoxFuture, FutureExt};
use tokio::process::Command;

mod config;
mod hub_responses;

use config::*;
use hub_responses::*;

#[tokio::main]
async fn main() -> Result<()> {
    let file_path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| "./templates/test1.yaml".into());

    println!("Reading {:?}", file_path);
    let is_toml = file_path.to_str().unwrap().ends_with(".toml");

    let data = fs::read(file_path).context("Error reading file")?;

    let config: Config = if is_toml {
        toml::from_slice(&data).context("Error parsing data")?
    } else {
        serde_yaml::from_slice(&data).context("Error parsing data")?
    };

    let manager = DeviceManager::new(&config, true);
    manager.delete_devices().await?;
    manager.create_devices().await?;

    // visualize(&config.root_device)?;
    Ok(())
}

struct DeviceManager<'a> {
    config: &'a Config,
    verbose: bool,
}

impl<'a> DeviceManager<'a> {
    pub fn new(config: &'a Config, verbose: bool) -> Self {
        Self { config, verbose }
    }

    pub async fn create_devices(&self) -> Result<Vec<CreateResponse>> {
        // Create devices
        let devices_to_create = Self::flatten_devices(&self.config.root_device);
        self.print(&format!(
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
        self.print(&format!(
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

        Ok(created_devices)
    }

    pub async fn delete_devices(&self) -> Result<()> {
        let devices_to_delete = Self::flatten_devices(&self.config.root_device);
        self.print(&format!(
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
            self.print("Deleted all devices.").await?;
        } else {
            self.print(&format!(
                "Successfully deleted {} devices, {} failed. For more information use the -v flag.",
                num_successes,
                num_successes - devices_to_delete.len(),
            ))
            .await?;
        }

        Ok(())
    }

    fn flatten_devices(device: &DeviceConfig) -> Vec<&str> {
        let mut result: Vec<&str> = vec![&device.device_id];
        for child in &device.children {
            result.append(&mut Self::flatten_devices(&child));
        }

        result
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
        self.print_verbose(&format!(
            "Creating device {} on hub {}",
            device_id, self.config.iothub.iot_hub_name
        ))
        .await?;

        let command = Self::get_command()
            .arg("az iot hub device-identity create")
            .args(&["--device-id", device_id])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .arg("--edge-enabled")
            .output()
            .await?;

        if command.status.success() {
            self.print_verbose(&format!("Successfully created {}", device_id))
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
            self.print_verbose(&error).await?;

            Err(anyhow::Error::msg(error))
        }
    }

    async fn create_parent_child_relationship(&self, parent: &str, child: &str) -> Result<()> {
        self.print_verbose(&format!("Adding {} as child of parent {}.", child, parent,))
            .await?;

        let command = Self::get_command()
            .arg("az iot hub device-identity parent set")
            .args(&["--device-id", child])
            .args(&["--parent-device-id", parent])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .output()
            .await?;

        if command.status.success() {
            self.print_verbose(&format!(
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
            self.print_verbose(&error).await?;

            Err(anyhow::Error::msg(error))
        }
    }

    async fn delete_device_identity(&self, device_id: &str) -> Result<bool> {
        self.print_verbose(&format!(
            "Deleting device {} on hub {}",
            device_id, self.config.iothub.iot_hub_name
        ))
        .await?;

        let command = Self::get_command()
            .arg("az iot hub device-identity delete")
            .args(&["--device-id", device_id])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .output()
            .await?;

        if command.status.success()
            || String::from_utf8_lossy(&command.stderr).contains("ErrorCode:DeviceNotFound;")
        {
            self.print_verbose(&format!("Successfully deleted {}", device_id))
                .await?;
            Ok(true)
        } else {
            self.print_verbose(&format!(
                "Failed to delete {}:\n{}\n{}\n",
                device_id,
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))
            .await?;

            Ok(false)
        }
    }

    async fn print(&self, text: &str) -> Result<()> {
        println!("{}", text);
        io::stdout().flush()?;
        Ok(())
    }

    async fn print_verbose(&self, text: &str) -> Result<()> {
        if self.verbose {
            println!("{}", text);
            io::stdout().flush()?;
        }

        Ok(())
    }

    fn get_command() -> Command {
        //TODO: sh for linux
        Command::new("powershell.exe")
    }
}

#[derive(Debug, Clone, Copy)]
enum ManageAction {
    Create,
    Delete,
}

use id_tree::InsertBehavior::{AsRoot, UnderNode};
use id_tree::{Node, NodeId, Tree, TreeBuilder};
use id_tree_layout::{Layouter, Visualize};

struct NodeData(String);

fn visualize(root: &DeviceConfig) -> Result<()> {
    let mut tree: Tree<NodeData> = TreeBuilder::new().build();

    let root_id: NodeId = tree.insert(Node::new(NodeData(root.device_id.clone())), AsRoot)?;
    add_children(&root.children, &root_id, &mut tree)?;

    fs::create_dir_all("test")?;
    Layouter::new(&tree)
        .with_file_path(std::path::Path::new("test/visualization.svg"))
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
