# Usage
This folder contains a zip file for each device created, named [[device-id]].zip. Transfer each zip to its respective device. A good option for this is to use [scp](https://man7.org/linux/man-pages/man1/scp.1.html).

Each device must have iotedge installed. [[TODO: Link iotedge install docs here]]

Once the zip folder is on the device, unzip it using unzip. You may need to install [unzip](https://linux.die.net/man/1/unzip).

## Install Script
Once the folder is unziped, cd into the directory and run `./install.sh`. This will copy certificates, configure iot edge, and restart iotedge.
