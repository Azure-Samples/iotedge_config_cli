use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::process::Command;

use anyhow::{Context, Result};

mod config;
mod hub_responses;

use config::*;
use hub_responses::*;

fn main() -> Result<()> {
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

    let mut manager = DeviceManager::new(&config);
    manager.manage_devices(ManageAction::Delete)?;
    manager.manage_devices(ManageAction::Create)?;

    // visualize(&config.root_device)?;
    Ok(())
}

struct DeviceManager<'a> {
    config: &'a Config,
    verbose: bool,
    devices: HashMap<String, CreateResponse>,
}

impl<'a> DeviceManager<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self {
            config,
            verbose: true,
            devices: HashMap::new(),
        }
    }

    pub fn manage_devices(&mut self, action: ManageAction) -> Result<()> {
        self.manage_devices_internal(
            &self.config.root_device.device_id,
            None,
            &self.config.root_device.children,
            action,
        )
    }

    fn manage_devices_internal(
        &mut self,
        device_id: &str,
        parent_name: Option<&str>,
        children: &[ChildDevice],
        action: ManageAction,
    ) -> Result<()> {
        match action {
            ManageAction::Create => self.create_device_identity(device_id, parent_name)?,
            ManageAction::Delete => self.delete_device_identity(device_id)?,
        }

        for child in children {
            self.manage_devices_internal(
                &child.device_id,
                Some(device_id),
                &child.children,
                action,
            )?;
        }

        Ok(())
    }

    fn create_device_identity(&mut self, device_id: &str, parent_name: Option<&str>) -> Result<()> {
        self.print(&format!(
            "Making {} with parent {:?} on hub {}...",
            device_id, parent_name, self.config.iothub.iot_hub_name
        ))?;

        let command = Self::get_command()
            .arg("az iot hub device-identity create")
            .args(&["--device-id", device_id])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .arg("--edge-enabled")
            .output()?;

        if command.status.success() {
            self.print("Success!\n")?;
            if let Some(parent_name) = parent_name {
                self.create_parent_child_relationship(parent_name, device_id)?;
            }

            let created_device: CreateResponse = serde_json::from_slice(&command.stdout)?;
            self.devices.insert(device_id.to_owned(), created_device);
        } else {
            self.print("Failure.\n")?;
            self.print_verbose(&format!(
                "{}\n{}\n",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))?;
        }

        Ok(())
    }

    fn create_parent_child_relationship(&self, parent: &str, child: &str) -> Result<()> {
        self.print(&format!(
            "Adding {} as child of parent {}...",
            child, parent,
        ))?;

        let command = Self::get_command()
            .arg("az iot hub device-identity parent set")
            .args(&["--device-id", child])
            .args(&["--parent-device-id", parent])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .output()?;

        if command.status.success() {
            self.print("Success!\n")?;
        } else {
            self.print("Failure.\n")?;
            self.print_verbose(&format!(
                "{}\n{}\n",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))?;
        }

        Ok(())
    }

    fn delete_device_identity(&self, device_id: &str) -> Result<()> {
        self.print(&format!(
            "Deleting {} on hub {}...",
            device_id, self.config.iothub.iot_hub_name
        ))?;

        let command = Self::get_command()
            .arg("az iot hub device-identity delete")
            .args(&["--device-id", device_id])
            .args(&["--hub-name", &self.config.iothub.iot_hub_name])
            .output()?;

        if command.status.success()
            || String::from_utf8_lossy(&command.stderr).contains("ErrorCode:DeviceNotFound;")
        {
            self.print("Success!\n")?;
        } else {
            self.print("Failure.\n")?;
            self.print_verbose(&format!(
                "{}\n{}\n",
                String::from_utf8_lossy(&command.stdout),
                String::from_utf8_lossy(&command.stderr)
            ))?;
        }

        Ok(())
    }

    fn print(&self, text: &str) -> Result<()> {
        print!("{}", text);
        io::stdout().flush()?;
        Ok(())
    }

    fn print_verbose(&self, text: &str) -> Result<()> {
        if self.verbose {
            print!("{}", text);
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

fn visualize(root: &RootDevice) -> Result<()> {
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
    children: &[ChildDevice],
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
