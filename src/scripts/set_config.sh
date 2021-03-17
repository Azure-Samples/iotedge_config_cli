# ======================= Read User Input =======================================
read -p "Enter the parent hostname to use [$parent_hostname]: " host_in
parent_hostname=${host_in:-$parent_hostname}

if [ -z "$parent_hostname" ]
then
    echo "Invalid parent hostname $parent_hostname"
    exit 1
fi

read -p "Enter the hostname to use [$hostname]: " host_in
hostname=${host_in:-$hostname}

if [ -z "$hostname" ]
then
    echo "Invalid hostname $hostname"
    exit 1
fi

echo "Setting configuration for $device_id with parent hostname $parent_hostname and hostname $hostname"