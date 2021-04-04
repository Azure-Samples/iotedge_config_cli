# ======================= Copy hub auth certs  =======================================
cert_dir="/etc/aziot/certificates"
mkdir -p $cert_dir
cp "$device_id.hub-auth.cert.pem" "$cert_dir/$device_id.hub-auth.cert.pem"
cp "$device_id.hub-auth.key.pem" "$cert_dir/$device_id.hub-auth.key.pem"