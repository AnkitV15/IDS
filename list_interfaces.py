from scapy.all import get_if_list

print("Available interfaces as seen by Scapy:")
interfaces = get_if_list()
for iface in interfaces:
    print(iface)