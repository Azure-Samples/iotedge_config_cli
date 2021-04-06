mkdir -p iotedge_config_cli_release
cp target/release/iotedge_config_cli iotedge_config_cli_release/iotedge_config
cp -r templates/ iotedge_config_cli_release/templates

tar -czvf iotedge_config_cli.tar.gz iotedge_config_cli_release