# ======================= Install nested root CA =======================================
cp nested_edge_root.pem /usr/local/share/ca-certificates/nested_edge_root.pem
update-ca-certificates

# ======================= Copy device certs  =======================================
device_id={device_id:?}

cert_dir="/etc/aziot/certificates"
mkdir -p $cert_dir
cp "iotedge_config_cli_root.pem" "$cert_dir/iotedge_config_cli_root.pem"
cp "$device_id.cert.pem" "$cert_dir/$device_id.cert.pem"
cp "$device_id.key.pem" "$cert_dir/$device_id.key.pem"