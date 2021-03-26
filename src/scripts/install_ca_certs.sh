# ======================= Install nested root CA =======================================
cp iotedge_config_cli_root.pem /usr/local/share/ca-certificates/iotedge_config_cli_root.pem.crt
update-ca-certificates

# ======================= Copy device certs  =======================================
cert_dir="/etc/aziot/certificates"
mkdir -p $cert_dir
cp "$device_id.hub-auth.cert.pem" "$cert_dir/$device_id.hub-auth.cert.pem"
cp "$device_id.hub-auth.key.pem" "$cert_dir/$device_id.hub-auth.key.pem"