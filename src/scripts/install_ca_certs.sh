# ======================= Install nested root CA =======================================
if [ -f /etc/os-release ]
then
        . /etc/os-release
        if [[ "$NAME" == "Common Base Linux Mariner"* ]];
        then
                cp iotedge_config_cli_root.pem /etc/pki/ca-trust/source/anchors/iotedge_config_cli_root.pem.crt
                update-ca-trust
        else
                cp iotedge_config_cli_root.pem /usr/local/share/ca-certificates/iotedge_config_cli_root.pem.crt
                update-ca-certificates
        fi
else
        cp iotedge_config_cli_root.pem /usr/local/share/ca-certificates/iotedge_config_cli_root.pem.crt
        update-ca-certificates
fi

systemctl restart docker

# ======================= Copy device certs  =======================================
cert_dir="/etc/aziot/certificates"
mkdir -p $cert_dir
cp "iotedge_config_cli_root.pem" "$cert_dir/iotedge_config_cli_root.pem"
cp "$device_id.full-chain.cert.pem" "$cert_dir/$device_id.full-chain.cert.pem"
cp "$device_id.key.pem" "$cert_dir/$device_id.key.pem"