# ======================= Set Hostname =======================================

read -p "Enter the hostname to use: " hostname
if [ -z "$hostname" ]
then
    echo "Invalid hostname $hostname"
    exit 1
fi

# TODO: make install script non destructive of config
sed -i "s/{{HOSTNAME}}/$hostname/" config.toml
