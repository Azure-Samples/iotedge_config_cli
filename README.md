# IoT Edge Config

IoT Edge config is a command-line tool that helps to configure hierarchies of [Azure IoT Edge](https://azure.microsoft.com/services/iot-edge/) devices. It simplifies the configuration of the hierarchy by automating and condensing several steps into two:

1. Setting up the cloud configuration and preparing each device configuration, which includes:
    - Creating devices in your IoT Hub
    - Setting the parent-child relationships to authorize communication between devices
    - Generating a chain of certificates for each device to establish secure communication between them
    - Generating configuration files for each device

2. Installing each device configuration, which includes:
    - Installing certificates on each device
    - Applying the configuration files for each device

To learn more about how to use the IoT Edge config tool to deploy hierarchies of IoT Edge devices, please visit [https://aka.ms/iotedge-nested-tutorial](https://aka.ms/iotedge-nested-tutorial).

## Build

main: ![main](https://github.com/Azure-Samples/iotedge_config_cli/actions/workflows/rust.yml/badge.svg)

## Usage

Make sure you are logged in (`az login`) to the latest version of aziot-cli (2.20.0 or above) and have openssl in your path (or use the --openssl-path flag). Use `az account set -s {{subscription_name}}` to set your subscription and make sure the IoT Hub you want to use is already created.

Run visualize to verify your config
`cargo build && sudo target/debug/iotedge_config --visualize`

Run using the default config
`cargo build && sudo target/debug/iotedge_config`

### Options

`cargo build && sudo target/debug/iotedge_config -h`

```bash
iotedge_config 0.1.0

USAGE:
    iotedge_config [FLAGS] [OPTIONS]

FLAGS:
        --clean        Clean: deletes working directory at start
    -d, --delete       Delete: deletes devices in hub instead of creating them
    -f, --force        Force: tries to delete devices in hub before creating new ones
    -h, --help         Prints help information
    -V, --version      Prints version information
    -v, --verbose      Verbose: gives more detailed output
        --visualize    Visualize: only outputs visualization file, does no other work

OPTIONS:
    -c, --config <config>                Config: path to config file [default: ./iotedge_config.yaml]
        --openssl-path <openssl-path>    Openssl Path: Path to openssl executable. Only needed if `openssl` is not in
                                         PATH
    -o, --output <output>                Output: path to create directory at [default: ./iotedge_config]
        --zip-options <zip-options>      Zip Options: what should be zipped: all, devices, or none [default: devices]
```

## Contributing

If you would like to build or change the IoT Edge source code, please follow the devguide.

This project has adopted the Microsoft Open Source Code of Conduct. For more information see the Code of Conduct FAQ or contact opencode@microsoft.com with any additional questions or comments.
