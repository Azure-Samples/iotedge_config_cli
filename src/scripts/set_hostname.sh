# ======================= Set Hostname =======================================

read -p "Enter the hostname to use: " hostname
if [ -z "$hostname" ]
then
    echo "Invalid hostname $hostname"
    exit 1
fi

sed -i "s/{{HOSTNAME}}/$hostname/" config.toml
