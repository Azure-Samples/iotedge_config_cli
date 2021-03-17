# ======================= Set Parent Hostname =======================================

read -p "Enter the parent hostname to use: " parent_hostname
if [ -z "$parent_hostname" ]
then
    echo "Invalid parent hostname $parent_hostname"
    exit 1
fi

sed -i "s/{{PARENT_HOSTNAME}}/$parent_hostname/" config.toml
