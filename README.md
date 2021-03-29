# Build
main: ![main](https://github.com/Azure-Samples/iotedge_config_cli/actions/workflows/rust.yml/badge.svg)

# Usage
Make sure you are logged in (`az login`) to the latest version of aziot-cli (2.20.0 or above) and have openssl in your path (or use the --openssl-path flag). Use `az account set -s {{subscription_name}}` to set your subscription and make sure the IoT Hub you want to use is already created.

Run visualize to verify your config
`cargo build && sudo target/debug/iotedge_config_cli --visualize`

Run using the default config
`cargo build && sudo target/debug/iotedge_config_cli`

## Options
`cargo build && sudo target/debug/iotedge_config_cli -h`
```
iotedge_config_cli 0.1.0

USAGE:
    iotedge_config_cli [FLAGS] [OPTIONS]

FLAGS:
        --clean        Clean: deletes working directory at start
    -d, --delete       Delete: deletes devices in hub instead of creating them
    -f, --force        Force: tries to delete devices in hub before creating new ones
    -h, --help         Prints help information
    -V, --version      Prints version information
    -v, --verbose      Verbose: gives more detailed output
        --visualize    Visualize: only outputs visualization file, does no other work

OPTIONS:
    -c, --config <config>                Config: path to config file [default: ./iotedge_config_cli.yaml]
        --openssl-path <openssl-path>    Openssl Path: Path to openssl executable. Only needed if `openssl` is not in
                                         PATH
    -o, --output <output>                Output: path to create directory at [default: ./iotedge_config_cli]
        --zip-options <zip-options>      Zip Options: what should be zipped: all, devices, or none [default: devices]
```
