#from scapy.all import get_if_list
#print(get_if_list())
# list_ifaces.py
#from scapy.arch.windows import get_windows_if_list

#ifaces = get_windows_if_list()
#for i, iface in enumerate(ifaces):
 #   print(f"[{i}] name: {iface.get('name')}")
 #   print(f"    description: {iface.get('description')}")
  #  print(f"    guid: {iface.get('guid')}")
  #  print()
from scapy.all import get_if_list
print(get_if_list())