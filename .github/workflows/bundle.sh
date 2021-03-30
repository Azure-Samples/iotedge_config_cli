mkdir -p temp_release
cp target/release/iotedge_config_cli temp_release/iotedge_config_cli
cp -r templates/ temp_release/templates

tar -czvf iotedge_config_cli.tar.gz temp_release