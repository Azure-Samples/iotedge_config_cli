# This script will attempt to configure a pre-installed iotedge as a nested node.
# It must be run as sudo, and will modify the ca

device_id={device_id:?}
cp config.toml /etc/aziot/config.toml