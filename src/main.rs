use std::fs::File;
use std::io::Read;

use anyhow::Result;

mod config;

fn main() -> Result<()> {
    let file_path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| "./templates/test1.toml".into());

    println!("Reading {:?}", file_path);
    let is_toml = file_path.to_str().unwrap().ends_with(".toml");

    let mut file = File::open(file_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    
    let parsed: config::Config = if is_toml {
        toml::from_slice(&data)?
    } else {
        serde_yaml::from_slice(&data)?
    };

    println!("{:#?}", parsed);
    Ok(())
}
