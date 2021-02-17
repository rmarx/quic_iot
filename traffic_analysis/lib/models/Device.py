
# a device consists of 
# - name
# - ip and/or mac
# - type (application | device | gateway) (default value is device)
# we're too lazy to map all this manually from JSON files, so use __getattr__ instead
class Device:
    def __init__(self, data):
        self.data = data

    def __getattr__(self, name):
        if name == "type":
            if name not in self.data:
                return "device"

        if name not in self.data:
            return ""

        return self.data[name]

# a list of devices which can be queried by either IP or MAC

class DeviceList:
    def __init__(self, json_list):
        self.list = []
        for json_device in json_list:
            self.list.append( Device(json_device) )

    # next( iter(), None) is used to return first found match or empty if none found: https://stackoverflow.com/a/365934

    def find_by_connection(self, connection):

        device1 = self.find_by_ip( connection.ip1 )
        device2 = self.find_by_ip( connection.ip2 )

        if device1 is None:
            device1 = self.find_by_mac( connection.mac1 )
        if device2 is None:
            device2 = self.find_by_mac( connection.mac2 ) 

        # if just one of the devices is identified, the choice is simple
        # however, if both are from the local testbed, we want to group by actual IoT devices and not e.g., mobile phones
        # so we use the .type to look for the device
        # if both are devices, well... return the one that received the connection (device2), assuming that's the one under consideration

        if device1 is None and device2 is not None:
            return device2 
        elif device2 is None and device1 is not None:
            return device1
        elif device2 is not None and device1 is not None:
            if device1.type == "device" and device2.type != "device":
                return device1
            elif device1.type != "device" and device2.type == "device":
                return device2
            else:
                return device2
        else:
            return None

    def find_by_ip(self, ip):
        return next(iter([device for device in self.list if device.ip == ip]), None)

    def find_by_mac(self, mac):
        return next(iter([device for device in self.list if device.mac == mac]), None)

    def find_by_name(self, name):
        return next(iter([device for device in self.list if device.name == name]), None)

    def find_by_type(self, type):
        return [device for device in self.list if device.type == type]


        
        