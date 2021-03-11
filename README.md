# nested_edge_cli

## Usage
Make sure you are logged into the latest version of aziot-cli (2.20.0) and have openssl in your path (or use the --openssl-path flag)

`cargo build && sudo target/debug/nested_edge_cli -h`
```
nested_edge_cli 0.1.0

USAGE:
    nested_edge_cli [FLAGS] [OPTIONS]

FLAGS:
    -d, --delete       Delete: deletes devices in hub instead of creating them
    -f, --force        Force: tries to delete devices in hub before creating new ones
    -h, --help         Prints help information
    -V, --version      Prints version information
    -v, --verbose      Verbose: gives more detailed output
        --visualize    Visualize: only outputs visualization file, does no other work

OPTIONS:
    -c, --config <config>                Config: path to config file [default: ./nested_config.yaml]
        --openssl-path <openssl-path>    Openssl Path: Path to openssl executable. Only needed if `openssl` is not in
                                         PATH
    -o, --output <output>                Output: path to create directory at [default: ./nested]
        --zip-options <zip-options>      Zip Options: what should be zipped: all, devices, or none [default: devices]
```