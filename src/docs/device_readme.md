# Prerequisites
Each device must have IoT Edge (must be v1.2 or later) installed. Pick the [supported OS](https://docs.microsoft.com/en-us/azure/iot-edge/support?view=iotedge-2020-11) and follow the [tutorial](https://docs.microsoft.com/en-us/azure/iot-edge/support?view=iotedge-2020-11) to install Azure IoT Edge.

# Steps

1. After install and configure IoT Edge to Azure IoT Hub or Azure IoT Central, copy the zip file for each device created, named [[device-id]].zip. 
2. Transfer each zip to its respective device. A good option for this is to use [scp](https://man7.org/linux/man-pages/man1/scp.1.html).
3. Unzip the zip file by running following commands

```Unzip
    sudo apt install zip
    unzip ~/<PATH_TO_CONFIGURATION_BUNDLE>/<CONFIGURATION_BUNDLE>.zip
```
4. Run the script
```Run
    sudo ./install.sh
```
5. If the hostname was not provided in the configuration file, it will prompt for hostname. Follow the prompt by entering the hostname (FQDN or IP address). On the parent device, it may prompt its own hostname and on the child deivce, it may prompt the hostname of both the child and parent device.

