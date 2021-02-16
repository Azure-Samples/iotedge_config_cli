use std::fs;

use anyhow::{Context, Result};

mod config;

fn main() -> Result<()> {
    let file_path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| "./templates/test1.toml".into());

    println!("Reading {:?}", file_path);
    let is_toml = file_path.to_str().unwrap().ends_with(".toml");

    let data = fs::read(file_path).context("Error reading file")?;

    let parsed: config::Config = if is_toml {
        toml::from_slice(&data).context("Error parsing data")?
    } else {
        serde_yaml::from_slice(&data).context("Error parsing data")?
    };

    // // println!("{:#?}", parsed);
    visualize(parsed.edgedevices)?;
    Ok(())
}

use id_tree::InsertBehavior::{AsRoot, UnderNode};
use id_tree::{Node, NodeId, Tree, TreeBuilder};
use id_tree_layout::{Layouter, Visualize};

struct NodeData(String);

fn visualize(config: config::EdgeDevices) -> Result<()> {
    let mut tree: Tree<NodeData> = TreeBuilder::new().with_node_capacity(5).build();

    let root_id: NodeId = tree.insert(Node::new(NodeData(config.root)), AsRoot)?;
    add_children(&config.child, &root_id, &mut tree)?;

    fs::create_dir_all("test")?;
    Layouter::new(&tree)
        .with_file_path(std::path::Path::new("test/visualization.svg"))
        .write()
        .context("Cannot write visualization file.")?;

    Ok(())
}

fn add_children(
    children: &[config::Layer],
    parent: &NodeId,
    tree: &mut Tree<NodeData>,
) -> Result<()> {
    for child in children {
        let new_node: NodeId = tree.insert(
            Node::new(NodeData(child.device_id.clone())),
            UnderNode(parent),
        )?;
        add_children(&child.child, &new_node, tree)?;
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
