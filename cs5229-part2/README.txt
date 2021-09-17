@Author <Saurav Sircar/A0198873E>
Date : 07/10/2019

1) A Proxy-Arp Reply is used to allow the client to get the MAC address of the NAT switch.
When one host wants the send ICMP request to another host that is not in its subnet, it will first send a ARP request to
its default gateway. When the NAT receives the broadcast/multicast ARP packet, it checks the HashMap and creates the corresponding 
ARP reply with the interface's MAX address. This way, all the clients and the server can get the MAC address of its connected interface of the NAT.

2) Outbound client to server translation is implemented to allow ICMP request from client to server.
When the packet is a non-broadcast, non-multicast IP packet, the packet destination IP address is the server address and the
packet is an ICMP request, it means it is the ICMP request send from client to server. So we will update the two identifier
map (will discuss the identifier map in section 4), change the Ethernet packet destination address to server's MAC address,
change Ethernet packet source address to NAT's public interface MAC address, change IP packet source address to NAT's public
interface IP address and reset the checksum. Push the packet to the OFPort of the public interface. So the server does
not see the internal topology and see the packet is sent from the public interface of the NAT.
The challenge faced here is how to get the identifier of the ICMP packet. The class ICMP.java only provide us with three
properties, icmpType, icmpCode and checksum. In order to get the identifier, we make use of the OFPacketIn pi. We use the
getData() method the get the raw data of the packet, which is in byte array format. So calculate the Ethernet packet header
length, the IP packet head length and the ICMP header length. So can get the identifier is at position 38 and 39 of the byte
array and calculate its value.

3) Inbound server to client translation is implement to allow ICMP reply from server to client.
When the packet is non-broadcast, non-multicast IP packet, the packet destination IP address is the public interface of the
NAT and the packet is an ICMP reply, it means it is the ICMP reply from server to client. We will fist check whether it is
in the ipAddressMap. If it is not inside the map, it means timeout and we will not process further. If it is inside the
map, we will get the client IP address from the ipAddressMap and set it as the IP packet's destination address, further
get the client MAC address from IPMacMap and set it as the Ethernet packet's destination address and reset the checksum.
We then get the OFPort of the destination client and push the packet to the OFPort. Then the client can receive the reply.

4) Implement the Query ID timeout.
We will create two ConcurrentHashMap. One is to store the query identifier to client ip address map and we call it ipAddressMap.
The other is to store the query identifier to its last used epoch time and we call it timeUsageMap.
Whenever ICMP request packet comes in, if it does not exist in ipAddressMap, we will add it into the map. We will also
update the timeUsageMap to current epoch second. We will create a thread to run every second. It will check for
every entry in timeUsageMap. If the last used time is less than the current time minus timeout, it will remove
the entry. So timeout packet will not be processed.

5) Normal clients will be in the same subnet. So when one client wants to communicate with another client, it will broadcast
an ARP request. Then the other client will reply with its MAC address. Once they get each other's MAC address, they can
communicate directly. If they are not in the same subnet, there will be some routing table for them to communicate.
Examples like in AWS, EC2 instances communicate with each other inside one VPC.
If the two clients are purely connected with NAT, we can add following functions for them to communicate:
1. When NAT receive broadcast ARP request, if the target client is also connected with the NAT, the NAT will reply the ARP
request with its own MAC address. So further packet from the source client to target client will be send to the NAT.
2. When NAT receive other packet from source client to target client, it will change the packet's destination MAC address
to target's MAC address and push the packet to the port connect with the target client.