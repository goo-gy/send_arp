#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "header.h"

int main(int argc, char* argv[])
{
	if(argc != 3)
	{
		printf("send_packet [victim] [gateway]\n");
		return -1;
	}


	char errbuf[256];			//size other presentation
	char *dev = pcap_lookupdev(errbuf);	//errbuf size?
	pcap_t *handle;
	handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);	//length
					//why 65536

	//-------------------------MAC---------------------------------
	struct ifreq ifr;		//in <net/if.h>
	struct ifconf ifc;		//	""
	char buf[1024];			//what buf, why 1024
		
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);	//AF_INET, SOCK_DGRAM, socket in <net/if.h> and IPPROTO_IP in <netinet/in.h>
	if(sock == -1) {/*Do what*/}  

	ifc.ifc_len = sizeof(buf);	//why 1024?
	ifc.ifc_buf = buf;
	if(ioctl(sock, SIOCGIFCONF, &ifc) == -1)
	{
		//error?
	}

	struct ifreq* it = ifc.ifc_req;		//ifc_req is ifreq pointer?
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));	// what is this??? I think this is for eterator

	int success = 0;
	for (; it != end; it++)
	{
		strcpy(ifr.ifr_name, it->ifr_name);
		if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) // success -> return 0?
			//need <sys/ioctl.h>
		{
			//something is here (flag and IFF_LOOPBACK)
			if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
			{
				//what is SIOCGIFHWADDR, return 0 is success?
				success =1;
				break;
			}
		}	
		else { /*error*/ }
	}
	unsigned char my_mac[6];
		
	if(success)
		memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
	//-------------------------------------------------------------

	ether_h ethernet;
	ethernet.dst[0];	//add
	int i;
	for(i = 0; i < 6; i++)
	{
		ethernet.src[i] = my_mac[i];	//my_mac is failed...
		ethernet.dst[i] = 0xff;
	}
	ethernet.type = htons(0x0806);		//modify please

	arp_h arp;
	arp.hard_type = htons(1); //ethernet
	arp.proto_type = htons(0x0800); //ip
	arp.hard_length = 6;
	arp.proto_length = 4;
	arp.opcode = htons(1);			
	for(i = 0; i < 6; i++)
	{
		arp.hard_src[i] = my_mac[i];
		arp.hard_dst[i] = 0x00;
	}
	const char* gateway_ip = argv[3];
	inet_pton(AF_INET, argv[1], &arp.proto_src);		//in <arpa/inet.h>
	inet_pton(AF_INET, argv[2], &arp.proto_dst);		//error if i get argv[]

	char *packet = malloc(sizeof(ethernet)+sizeof(arp));
	memset(packet, 0, sizeof(ethernet)+sizeof(arp));
	
	memcpy(packet, &ethernet, sizeof(ethernet));
	memcpy(packet+sizeof(ethernet), &arp, sizeof(arp));

	if( pcap_sendpacket(handle, packet, sizeof(ethernet)+sizeof(arp)) != 0)
	{
		printf("Can't send the packet!\n");
		return -1;
	}

//	close(handle);		//in <unistd.h>
	
	return 0;
}
