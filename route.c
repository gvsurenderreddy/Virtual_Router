#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <fstream>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>



#define ETH_HTYPE 1
#define IPV4_PTYPE 2048
#define ETHER_HLEN 6
#define IPV4_PLEN 4
#define OPER_REQUEST 1
#define OPER_REPLY 2
#define ARP_SIZE 28
#define ARP_TYPE 2054
#define R1_TABLE 1
#define R2_TABLE 2
#define TABLE_ROWS 6
#define TABLE_COLS 3
#define BUF_SIZE 50

using namespace std;

typedef struct eth_hdr{
	uint8_t dst_addr_1;
	uint8_t dst_addr_2;
	uint8_t dst_addr_3;
	uint8_t dst_addr_4;
	uint8_t dst_addr_5;
	uint8_t dst_addr_6;
	uint8_t src_addr_1;
	uint8_t src_addr_2;
	uint8_t src_addr_3;
	uint8_t src_addr_4;
	uint8_t src_addr_5;
	uint8_t src_addr_6;
	uint16_t _type;
}eth_hdr;

typedef struct arp_hdr{
	uint16_t htype;// ETH_HTYPE;
	uint16_t ptype;// IPV4_PTYPE;
	uint8_t hlen;// ETH_HLEN;
	uint8_t plen;// IPV4_PLEN;
	uint16_t oper;
	uint8_t sha_1;
	uint8_t sha_2;
	uint8_t sha_3;
	uint8_t sha_4;
	uint8_t sha_5;
	uint8_t sha_6;
	uint32_t spa;
	uint8_t tha_1;
	uint8_t tha_2;
	uint8_t tha_3;
	uint8_t tha_4;
	uint8_t tha_5;
	uint8_t tha_6;
	uint32_t tpa;
}arp_hdr;

typedef struct routing_column{
	string net_prefix;
	string hop_addr;
	string interface;
}routing_column;

void print_eth(eth_hdr& eth){
	cout << endl << endl << "ETHERNET HEADER" << endl << endl;
	cout << "Destination Address: "; 
	printf("%2x ", eth.dst_addr_1);
	printf("%2x ", eth.dst_addr_2);
	printf("%2x ", eth.dst_addr_3);
	printf("%2x ", eth.dst_addr_4);
	printf("%2x ", eth.dst_addr_5);
	printf("%2x \n", eth.dst_addr_6);

	cout << "Source Address: ";
	printf("%2x ", eth.src_addr_1);
	printf("%2x ", eth.src_addr_2);
	printf("%2x ", eth.src_addr_3);
	printf("%2x ", eth.src_addr_4);
	printf("%2x ", eth.src_addr_5);
	printf("%2x \n", eth.src_addr_6);

	cout << "Type: " << eth._type << endl;
}

void print_arp(arp_hdr& arp){
	cout << endl << endl << "ARP HEADER" << endl << endl;
	cout << "Sender IP Address: " << arp.spa << endl;
	cout << "Target IP Address: " << arp.tpa << endl;
}

void print_buf(char* buf){
	int i, j;
	printf("\n\nBUFFER CONTENTS\n\n");
	for(i=0; i<BUF_SIZE; i++){
		printf("%02x ", (unsigned char)buf[i]);
		if(i%16 == 0 && i != 0){
			printf("\n");
		}
	}
}

void pull_arp(arp_hdr& arp, eth_hdr& eth, char* buf, int eth_size){
	memcpy(&eth, buf, eth_size);
	memcpy(&arp, &buf[eth_size], 28);
}

void push_arp(arp_hdr& arp, eth_hdr& eth, char* buf, int eth_size){
	memset(buf, 0, BUF_SIZE);
	memcpy(buf, &eth, eth_size);
	memcpy(&buf[eth_size], &arp, 28);
}



void fill_table(vector<struct routing_column>& table){
	int i, j, k;
	string cell;
	vector<string> elements;
	routing_column col;
	//if(type == R1_TABLE){
	ifstream file ("r1_table.txt");

	if(file.is_open()){
		while(file >> cell){
			elements.push_back(cell);
		}
		for(i=0; i<elements.size(); i+=3){
			col.net_prefix = elements[i];		
			col.hop_addr = elements[i+1];
			col.interface = elements[i+2];
			table.push_back(col);
		}
	}
	else{
		printf("\nError reading routing table\n");
	}

}	


int main(){
	int packet_socket;
	//get list of interfaces (actually addresses)
	struct ifaddrs *ifaddr, *tmp;
	if(getifaddrs(&ifaddr)==-1){
		perror("getifaddrs");
		return 1;
	}
	//have the list, loop over the list
	for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
		//Check if this is a packet address, there will be one per
		//interface.  There are IPv4 and IPv6 as well, but we don't care
		//about those for the purpose of enumerating interfaces. We can
		//use the AF_INET addresses in this list for example to get a list
		//of our own IP addresses
		if(tmp->ifa_addr->sa_family==AF_PACKET){
			printf("Interface: %s\n",tmp->ifa_name);
			//create a packet socket on interface r?-eth1
			if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
				printf("Creating Socket on interface %s\n",tmp->ifa_name);
				//create a packet socket
				//AF_PACKET makes it a packet socket
				//SOCK_RAW makes it so we get the entire packet
				//could also use SOCK_DGRAM to cut off link layer header
				//ETH_P_ALL indicates we want all (upper layer) protocols
				//we could specify just a specific one
				packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if(packet_socket<0){
					perror("socket");
					return 2;
				}
				//Bind the socket to the address, so we only get packets
				//recieved on this specific interface. For packet sockets, the
				//address structure is a struct sockaddr_ll (see the man page
				//for "packet"), but of course bind takes a struct sockaddr.
				//Here, we can use the sockaddr we got from getifaddrs (which
				//we could convert to sockaddr_ll if we needed to)
				if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
					perror("bind");
				}
			}
		}
	}
	//free the interface list when we don't need it anymore
	freeifaddrs(ifaddr);

	//loop and recieve packets. We are only looking at one interface,
	//for the project you will probably want to look at more (to do so,
	//a good way is to have one socket per interface and use select to
	//see which ones have data)

	//Variables used in loop
	int eth_size;
	arp_hdr arp;
	eth_hdr eth;
	uint32_t temp1;
	uint16_t temp2;
	vector<struct routing_column> routing_table;

	printf("Ready to recieve now\n");
	


	while(1){
		char buf[BUF_SIZE];
		memset(buf, 0, BUF_SIZE);
		struct sockaddr_ll recvaddr;
		unsigned int recvaddrlen=sizeof(struct sockaddr_ll);
		//we can use recv, since the addresses are in the packet, but we
		//use recvfrom because it gives us an easy way to determine if
		//this packet is incoming or outgoing (when using ETH_P_ALL, we
		//see packets in both directions. Only outgoing can be seen when
		//using a packet socket with some specific protocol)
		int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
		//ignore outgoing packets (we can't disable some from being sent
		//by the OS automatically, for example ICMP port unreachable
		//messages, so we will just ignore them here)
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;
		//start processing all others
		printf("Got a %d byte packet\n", n);

		//what else to do is up to you, you can send packets with send,
		//just like we used for TCP sockets (or you can use sendto, but it
		//is not necessary, since the headers, including all addresses,
		//need to be in the buffer you are sending)
		


		//Determine Size of Ethernet Header
		eth_size = n - ARP_SIZE;
		//Fill arp header struct with received data
		pull_arp(arp, eth, buf, eth_size);
		print_buf(buf);
		print_eth(eth);
		print_arp(arp);

		fill_table(routing_table);

		//Print Routing Table
		/*
		for(int i=0; i<routing_table.size(); i++){
			cout << routing_table[i].net_prefix << " ";
			cout << routing_table[i].hop_addr << " ";
			cout << routing_table[i].interface << endl;
		}*/	

		//eth.dst_addr_1 = eth.src_addr_1;
		//eth.dst_addr_2 = eth.src_addr_2;
		arp.tpa = arp.spa;
		arp.oper = htons(OPER_REPLY);
		print_arp(arp);
		push_arp(arp, eth, buf, eth_size);
		send(packet_socket, buf, BUF_SIZE, 0);

		
	}
	//exit
	return 0;
}