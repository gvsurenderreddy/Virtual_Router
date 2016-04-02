#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <algorithm>



#define ETH_HTYPE 256
#define IPV4_PTYPE 8
#define ETHER_HLEN 6
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define IPV4_PLEN 4
#define OPER_REQUEST 256
#define OPER_REPLY 2
#define ARP_SIZE 28
#define ARP_TYPE 1544
#define ICMP_TYPE 2048
#define R1_TABLE 1
#define R2_TABLE 2
#define TABLE_ROWS 6
#define TABLE_COLS 3
#define BUF_SIZE 150

using namespace std;

typedef struct eth_hdr{
	char dst_addr[6];
	char src_addr[6];
	uint16_t _type;
}eth_hdr;

typedef struct arp_hdr{
	uint16_t htype;// ETH_HTYPE;
	uint16_t ptype;// IPV4_PTYPE;
	uint8_t hlen;// ETH_HLEN;
	uint8_t plen;// IPV4_PLEN;
	uint16_t oper;
	char sha[6];
	char spa[4];
	char tha[6];
	char tpa[4];
}arp_hdr;

typedef struct icmp_hdr{
	uint8_t _type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t seq_num;
	char tmstmp[8];
	char data[48];
}icmp_hdr;

typedef struct ip_hdr{
	uint8_t version: 4;
	uint8_t ihl: 4;
	uint8_t dscb;
	uint16_t total_length;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	char src_addr[4];
	char dst_addr[4];
}ip_hdr;

typedef struct routing_column{
	string net_prefix;
	string hop_addr;
	string interface;
}routing_column;


void print_ip(ip_hdr& ip){
	int i;
	printf("\n\nIP HEADER\n\n");
	printf("Version: %02x\n",ip.version);
	printf("ihl: %02x\n",ip.ihl);
	printf("DSCB: %02x\n",ip.dscb);
	printf("Total Length: %02x\n",ip.total_length);
	printf("ID: %02x\n",ip.id);
	printf("Frag Offset: %02x\n",ip.frag_offset);
	printf("TTL: %02x\n",ip.ttl);
	printf("Protocol: %02x\n",ip.protocol);
	printf("Checksum: %02x\n",ip.checksum);
	printf("SRC: ");
	for(i=0; i<4; i++){
		printf("%02x ", (unsigned char) ip.src_addr[i]);
	}
	printf("\nDST: ");
	for(i=0; i<4; i++){
		printf("%02x ", (unsigned char) ip.dst_addr[i]);
	}
	printf("\n");
}

void print_eth(eth_hdr& eth){
	int i;
	cout << endl << endl << "ETHERNET HEADER" << endl << endl;
	cout << "Destination Address: "; 
	for(i=0; i<6; i++){
		printf("%02x ", (unsigned char)eth.dst_addr[i] );
	}
	printf("\n");

	cout << "Source Address: ";
	for(i=0; i<6; i++){
		printf("%02x ", (unsigned char)eth.src_addr[i]);
	}
	printf("\n");

	printf("Type: %02x\n", eth._type);	
}

void print_arp(arp_hdr& arp){
	int i;
	cout << endl << endl << "ARP HEADER" << endl << endl;
	printf("HTYPE: %02x\n", arp.htype);
	printf("PTYPE: %02x\n", arp.ptype);
	printf("HLEN: %02x\n", arp.hlen);
	printf("PLEN: %02x\n", arp.plen);
	printf("OPERATION: %02x\n", arp.oper);

	cout << "Sender MAC Address: ";
	for(i=0; i<6; i++){
		printf("%02x ", (unsigned char)arp.sha[i] );
	}
	printf("\n");
	cout << "Sender IP Address: ";
	for(i=0; i<4; i++){
		printf("%02x ", (unsigned char)arp.spa[i] );
	}
	printf("\n");
	cout << "Target MAC Address: ";
	for(i=0; i<6; i++){
		printf("%02x ", (unsigned char)arp.tha[i] );
	}
	printf("\n");
	cout << "Target IP Address: ";
	for(i=0; i<4; i++){
		printf("%02x ", (unsigned char)arp.tpa[i] );
	}
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

void pull_eth(eth_hdr& eth, char* buf, int eth_size){
	memcpy(&eth, buf, eth_size);
}


void pull_arp(arp_hdr& arp, char* buf, int eth_size){
	memcpy(&arp, &buf[eth_size], 28);
}

void pull_ip(ip_hdr& ip, char* buf, int eth_size){
	memcpy(&ip, &buf[eth_size], 20);
	/*uint8_t temp;
	temp = ip.version;
	ip.version = ip.ihl;
	ip.ihl = temp;
	ip.total_length = htons(ip.total_length);
	ip.id = htons(ip.id);
	ip.frag_offset = htons(ip.frag_offset);
	ip.checksum = htons(ip.checksum);*/
}

void pull_icmp(icmp_hdr& icmp, char* buf, int eth_size){
	memcpy(&icmp, &buf[eth_size+20], 64);
}

void push_arp(arp_hdr& arp, eth_hdr& eth, char* buf, int eth_size){
	memset(buf, 0, BUF_SIZE);
	memcpy(buf, &eth, eth_size);
	memcpy(&buf[eth_size], &arp, 28);
}

void push_eth(eth_hdr eth, char* buf){
	memcpy(buf, &eth, ETH_HDR_LEN);
}

void push_icmp(icmp_hdr& icmp, ip_hdr& ip, eth_hdr& eth, char* buf, int eth_size){
	memset(buf, 0, BUF_SIZE);
	memcpy(buf, &eth, eth_size);
	memcpy(&buf[eth_size], &ip, 20);
	memcpy(&buf[eth_size+20], &icmp, 64);
}



void fill_table(vector<struct routing_column>& table, int router_num){
	int i, j, k, l, m, n;

	string cell;
	vector<string> elements;
	routing_column col;
	const char* fp;

	//Check which router we are
	if(router_num == 1){
		fp = "r1_table.txt";
	}
	else{
		fp = "r2_table.txt";
	}

	ifstream file (fp);

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

	//Remove "." from strings
	for(i=0; i<table.size(); i++){
		table[i].net_prefix.erase(std::remove(table[i].net_prefix.begin(), table[i].net_prefix.end(), '.'), table[i].net_prefix.end());
	}

	for(i=0; i<table.size(); i++){
		table[i].hop_addr.erase(std::remove(table[i].hop_addr.begin(), table[i].hop_addr.end(), '.'), table[i].hop_addr.end());
	}

}	
uint16_t ip_calc_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}




int main(){
	int sock[4] = {0,0,0,0};
	//int sock3;
	int packet_socket;
	int router_num = 1;
	int eth_size = 14;
	arp_hdr arp;
	eth_hdr eth;
	ip_hdr ip;
	icmp_hdr icmp;
	uint32_t temp1;
	uint16_t temp2;
	sockaddr_in *sa;
	char *router_ip;
	char *router_ip0;
	char *router_ip1;
	char *router_ip2;
	char *router_ip3;
	char macp[6];
	char mac0[6];
	char mac1[6];
	char mac2[6];
	char mac3[6];
	char packet[BUF_SIZE];
	int packet_length;
	struct sockaddr_ll *s;
	int i;
	int j = 0;
	fd_set sockets;
	vector<struct routing_column> routing_table;


	char *result;
	router_ip0 = (char*)malloc(16);
	router_ip1 = (char*)malloc(16);
	router_ip2 = (char*)malloc(16);
	router_ip3 = (char*)malloc(16);


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

			//create a packet socket on interface r?-eth1
			//if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
				printf("Interface: %s\n",tmp->ifa_name);
				printf("Creating Socket on interface %s\n",tmp->ifa_name);

					
				if(!strcmp(tmp->ifa_name,"r2-eth1")){
					printf("\nUsing R2\n");
					router_num = 2;	
						
	        	}

		        //r1-eth0
		        if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)){
		        	sock[0] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
					if(sock[0]<0){
						perror("socket");
						return 2;
					}

					if(bind(sock[0],tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
						perror("bind");
					}
					//Harvest MAC address
					s = (struct sockaddr_ll *)tmp->ifa_addr;
		            int len = 0;
		            for(i = 0; i < 6; i++)
		                mac0[i] = s->sll_addr[i];
		        }

		        //r?-eth1
		        if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
		        	sock[1] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
					if(sock[1]<0){
						perror("socket");
						return 2;
					}

					if(bind(sock[1],tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
						perror("bind");
					}

					//Harvest MAC address
					s = (struct sockaddr_ll *)tmp->ifa_addr;
		            int len = 0;
		            for(i = 0; i < 6; i++)
		                mac1[i] = s->sll_addr[i];
		        }

		        //r?-eth2
		        if(!strncmp(&(tmp->ifa_name[3]),"eth2",4)){
		        	sock[2] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
					if(sock[2]<0){
						perror("socket");
						return 2;
					}

					if(bind(sock[2],tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
						perror("bind");
					}

					//Harvest MAC address
					s = (struct sockaddr_ll *)tmp->ifa_addr;
		            int len = 0;
		            for(i = 0; i < 6; i++)
		                mac2[i] = s->sll_addr[i];
		        }

		        //r?-eth3
		        if(!strncmp(&(tmp->ifa_name[3]),"eth3",4)){
		        	sock[3] = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
					if(sock[3]<0){
						perror("socket");
						return 2;
					}

					if(bind(sock[3],tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
						perror("bind");
					}

					//Harvest MAC address
					s = (struct sockaddr_ll *)tmp->ifa_addr;
		            int len = 0;
		            for(i = 0; i < 6; i++)
		                mac3[i] = s->sll_addr[i];
		        }
	
	
				
				/*//create a packet socket
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
				}*/
			//}
		}

		//Harvest our IP address's
		if(tmp->ifa_addr->sa_family==AF_INET){
			if(!strncmp(&(tmp->ifa_name[3]),"eth0",4)){
				printf("\nin 0\n");
				sa = (struct sockaddr_in *) tmp->ifa_addr;
				result = inet_ntoa(sa->sin_addr);
				strcpy(router_ip0 , result);
				printf("IP addr0: %s\n", router_ip0);
			}
			else if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
				printf("\nin 1\n");
				sa = (struct sockaddr_in *) tmp->ifa_addr;
				result = inet_ntoa(sa->sin_addr);
				strcpy(router_ip1 , result);
				printf("IP addr1: %s\n", router_ip1);
			}
			else if(!strncmp(&(tmp->ifa_name[3]),"eth2",4)){
				printf("\nin 2\n");
				sa = (struct sockaddr_in *) tmp->ifa_addr;
				result = inet_ntoa(sa->sin_addr);
				strcpy(router_ip2 , result);
				printf("IP addr2: %s\n", router_ip2);
			}
			if(!strncmp(&(tmp->ifa_name[3]),"eth3",4)){
				printf("\nin 3\n");
				sa = (struct sockaddr_in *) tmp->ifa_addr;
				result = inet_ntoa(sa->sin_addr);
				strcpy(router_ip3 , result);
				printf("IP addr: %s\n", router_ip3);
			}

		}
		//printf("IP addr1: %s\n", router_ip1);
	}
	//free the interface list when we don't need it anymore
	

	freeifaddrs(ifaddr);

	//loop and recieve packets. We are only looking at one interface,
	//for the project you will probably want to look at more (to do so,
	//a good way is to have one socket per interface and use select to
	//see which ones have data)

	//Variables used in loop

	fill_table(routing_table, router_num);

	//Print Routing Table
	
	for(int i=0; i<routing_table.size(); i++){
		cout << routing_table[i].net_prefix << " ";
		cout << routing_table[i].hop_addr << " ";
		cout << routing_table[i].interface << endl;
	}
	
	
	
	printf("Ready to recieve now\n");


	while(1){
		char buf[BUF_SIZE];
		bool loop_flag = false;
		memset(buf, 0, BUF_SIZE);
		//memset(packet, 0, BUF_SIZE);
		bool sent_flag = false;
		int active_socket;
		struct sockaddr_ll recvaddr;
		int interface;
		unsigned int recvaddrlen=sizeof(struct sockaddr_ll);
		//we can use recv, since the addresses are in the packet, but we
		//use recvfrom because it gives us an easy way to determine if
		//this packet is incoming or outgoing (when using ETH_P_ALL, we
		//see packets in both directions. Only outgoing can be seen when
		//using a packet socket with some specific protocol)
		int n;
		FD_ZERO(&sockets);
		int maxsock=0;
		int num_socks = router_num+2;
		for(i=0; i<num_socks; i++){
			FD_SET(sock[i], &sockets);
			if(sock[i] > maxsock) maxsock = sock[i];
		}
		select(maxsock+1, &sockets, NULL, NULL, NULL);
		printf("\n\n\nSocket selected\n");
		for(i=0; i<FD_SETSIZE; i++){
	  		//Check for connected sockets
	  		if(FD_ISSET(i, &sockets)){
	  			printf("Recieving packet from socket %d\n", i);
	  			active_socket = i;
				n = recvfrom(active_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
			}
		}
		
		if(active_socket == sock[0]){
			router_ip = router_ip0;
			memcpy(macp, mac0, 6);
		}
		if(active_socket == sock[1]){
			router_ip = router_ip1;
			memcpy(macp, mac1, 6);
		}
		if(active_socket == sock[2]){
			router_ip = router_ip2;
			memcpy(macp, mac2, 6);
		}
		if(active_socket == sock[3]){
			router_ip = router_ip3;
			memcpy(macp, mac3, 6);
		}
	
			
		//ignore outgoing packets (we can't disable some from being sent
		//by the OS automatically, for example ICMP port unreachable
		//messages, so we will just ignore them here)
		
		if(recvaddr.sll_pkttype==PACKET_OUTGOING)
			continue;
		//start processing all others
		printf("\nGot a %d byte packet\n", n);

		//what else to do is up to you, you can send packets with send,
		//just like we used for TCP sockets (or you can use sendto, but it
		//is not necessary, since the headers, including all addresses,
		//need to be in the buffer you are sending)
		
		char new_ip[4];
			j=0;
			for(i=0; i<sizeof(router_ip); i++){		
				if(router_ip[i] != '.'){
					if(i==1)
						continue;					
					new_ip[j] = atoi(&router_ip[i]);
					j++;
				}
			}

	
		//Pull Ethernet and IP header
		pull_eth(eth, buf, eth_size);
		print_eth(eth);
		pull_ip(ip, buf, eth_size);
		pull_icmp(icmp, buf, eth_size);
		print_ip(ip);

		//Are we the destination of this packet? 
		if(strcmp(ip.dst_addr, new_ip) != 0 && eth._type != ARP_TYPE){

			//If not...
			printf("\nRecieved packet that is not for us\n");

			

			//Is checksum correct?
			uint16_t ip_check = ip.checksum;
			ip.checksum = 0;
			uint16_t check = ip_calc_checksum(&ip, IP_HDR_LEN);
			printf("\nChecksum Recieved: %04x\n", ip_check);
			printf("Checksum Calculated: %04x\n", check);
			ip.checksum = check; 
			if(ip_check != check){
				
				printf("Packet Dropped: Incorrect Checksum\n");
				//Send ICMP error message
				char mac_tmp[6];
				char ip_tmp[6];
				//Swapt HW addresses
				memcpy(mac_tmp, &eth.src_addr, 6);
				memcpy(&eth.src_addr, &eth.dst_addr, 6);
				memcpy(&eth.dst_addr, mac_tmp, 6);
				//Swap IP addresses
				memcpy(ip_tmp, &ip.src_addr, 4);
				memcpy(&ip.src_addr, &ip.dst_addr, 4);
				memcpy(&ip.dst_addr, ip_tmp, 4);
				icmp._type = 3;
				icmp.code = 0;

				//Fill buffer and send
				push_icmp(icmp, ip, eth, buf, eth_size);
				printf("\nSending ICMP Error Message\n");
				send(active_socket, buf, n, 0);
				sent_flag = true;
			}
			//Handle TTL
			//Decrement TTL
			printf("Decrementing TTL\n");
			ip.ttl = ip.ttl - 1;
			if(ip.ttl <= 1){
				printf("Packet Dropped: Time Expired\n");
				//Send ICMP error message
				char mac_tmp[6];
				char ip_tmp[6];
				//Swapt HW addresses
				memcpy(mac_tmp, &eth.src_addr, 6);
				memcpy(&eth.src_addr, &eth.dst_addr, 6);
				memcpy(&eth.dst_addr, mac_tmp, 6);
				//Swap IP addresses
				memcpy(ip_tmp, &ip.src_addr, 4);
				memcpy(&ip.src_addr, &ip.dst_addr, 4);
				memcpy(&ip.dst_addr, ip_tmp, 4);
				icmp._type = 11;
				icmp.code = 0;

				//Fill buffer and send
				push_icmp(icmp, ip, eth, buf, eth_size);
				printf("\nSending ICMP Error Message\n");
				send(active_socket, buf, n, 0);
				sent_flag = true;
			}
			else{
				//Fix checksum
				ip.checksum = 0;
				check = ip_calc_checksum(&ip, IP_HDR_LEN);
				ip.checksum = check;
			}

			//Fill buffer and store a copy of the packet
			push_icmp(icmp, ip, eth, buf, eth_size);
			memcpy(packet, buf, n);
			packet_length = n;

			char net_pre[4];
			char hop_ip[4];
			int flag=0;

			//Check Forwarding Table
			for(i=0; i<routing_table.size(); i++){

				
				//Hack Job to make strings comparable
				for(j=0; j<5; j++){
					if(j == 1){
						flag = 1;
						continue;
					}
					net_pre[j-flag] = routing_table[i].net_prefix[j]-48;
					hop_ip[j-flag] = routing_table[i].hop_addr[j]-48;
				}
				net_pre[0] += 9;
				hop_ip[0] += 9;
				flag=0;

				if(strncmp(ip.dst_addr, net_pre, 3)== 0){
					//We have a match!
					printf("\n\nMATCH!\n\n");
					arp.htype = ETH_HTYPE;
					arp.ptype = IPV4_PTYPE;						
					arp.hlen = ETHER_HLEN;						
					arp.plen = IPV4_PLEN;						
					arp.oper = OPER_REQUEST;
					memcpy(&arp.sha, mac1, 6);
					memcpy(&arp.spa, new_ip, 4);
					memset(&arp.tha, 0, 6);
					if(strcmp(routing_table[i].hop_addr.c_str(), "-") == 0){
						//Router is directly connected to the netowrk IPaddr
						//Send ARP request for MAC address directly
						memcpy(&arp.tpa, ip.dst_addr, 4);
					}
					else{
						//Send ARP request for next hop IP address		
						memcpy(&arp.tpa, hop_ip, 4);
						//Send ARP request to find ethernet address
					}
					//Build Ethernet Header
					//Broadcast destination
					memset(&eth.dst_addr, 0xFF, 6);
					//Set our MAC address as the source
					memcpy(&eth.src_addr, mac1, 6);	
					eth._type = ARP_TYPE;

					

					//determine interface from routing table
					if(strcmp(routing_table[i].interface.c_str(), "r1-eth0") == 0 || strcmp(routing_table[i].interface.c_str(), "r2-eth0") ==0){
						interface = sock[0];
					}
					else if(strcmp(routing_table[i].interface.c_str(), "r1-eth1") == 0 || strcmp(routing_table[i].interface.c_str(), "r2-eth1") ==0){
						interface = sock[1];
					}
					else if(strcmp(routing_table[i].interface.c_str(), "r1-eth2") == 0 || strcmp(routing_table[i].interface.c_str(), "r2-eth2") ==0){
						interface = sock[2];
					}
					else{
						interface = sock[3];
					}

					//Push to buffer and send
					push_arp(arp, eth, buf, ETH_HDR_LEN);
					printf("\nSending ARP request on Interface: %d", interface);
					send(interface, buf, 42, 0);
					sent_flag = true;
					break;

				}

			}


			if(sent_flag){
				continue;
			}
			else if(loop_flag){
				//No matches
				//Send ICMP error message
				char mac_tmp[6];
				char ip_tmp[6];
				//Swapt HW addresses
				memcpy(mac_tmp, &eth.src_addr, 6);
				memcpy(&eth.src_addr, &eth.dst_addr, 6);
				memcpy(&eth.dst_addr, mac_tmp, 6);
				//Swap IP addresses
				memcpy(ip_tmp, &ip.src_addr, 4);
				memcpy(&ip.src_addr, &ip.dst_addr, 4);
				memcpy(&ip.dst_addr, ip_tmp, 4);
				icmp._type = 3;
				icmp.code = 0;

				//Fill buffer and send
				push_icmp(icmp, ip, eth, buf, eth_size);
				printf("\nSending ICMP error message\n");
				send(active_socket, buf, n, 0);
				continue;
			}
			
		}

		

		if(eth._type == ARP_TYPE){

			printf("\nRecieved ARP for us\n");

			//Determine Size of Ethernet Header
			eth_size = n - ARP_SIZE;
			//Fill arp header struct with received data
			pull_arp(arp, buf, eth_size);
			//print_buf(buf);
			//print_eth(eth);
			//print_arp(arp);
			if(arp.oper == OPER_REQUEST){
				//Reply to MAC address where message came from
				memcpy(&eth.dst_addr, &eth.src_addr, 6);
				//Set our MAC address as the source
				memcpy(&eth.src_addr, mac1, 6);	
				memcpy(&arp.tha, &arp.sha, 6);
				memcpy(&arp.sha, mac1, 6);
				memcpy(&arp.tpa, &arp.spa, 4);
				memcpy(&arp.spa, new_ip , 4);
				arp.oper = htons(OPER_REPLY);

				//Fill buffer and send packet
				push_arp(arp, eth, buf, eth_size);
				printf("\nSending ARP reply on %d\n", active_socket);
				send(active_socket, buf, n, 0);
			}
			else{
				//We recieved an ARP reply
				//Update Hardware address
				memcpy(packet, &arp.sha, 6);
				//Send Packet
				printf("\nForwarding Packet on %d\n", active_socket);
				send(active_socket, packet, packet_length, 0);
				memset(packet, 0, BUF_SIZE);
			}

		}
		else if(htons(eth._type) == ICMP_TYPE){
						
			printf("\nRecieved ICMP for us\n");

			//Pull data from buffer
			pull_ip(ip, buf, eth_size);
			pull_icmp(icmp, buf, eth_size);

			//Construct Ethernet header
			//Reply to MAC address where message came from
			memcpy(&eth.dst_addr, &eth.src_addr, 6);
			//Set our MAC address as the source
			memcpy(&eth.src_addr, mac1, 6);

			//Construct IP header
			//Set correct IP adresses in IP header
			memcpy(&ip.dst_addr, &ip.src_addr, 4);
			memcpy(&ip.src_addr, new_ip, 4); 

			//Is checksum correct?
			uint16_t ip_check = ip.checksum;
			ip.checksum = 0;
			uint16_t check = ip_calc_checksum(&ip, IP_HDR_LEN);
			printf("\nChecksum Recieved: %04x\n", ip_check);
			printf("Checksum Calculated: %04x\n", check);
			ip.checksum = check; 
			if(ip_check != check){
				
				printf("Packet Dropped: Incorrect Checksum\n");
				//Send ICMP error message
				char mac_tmp[6];
				char ip_tmp[6];
				//Swapt HW addresses
				memcpy(mac_tmp, &eth.src_addr, 6);
				memcpy(&eth.src_addr, &eth.dst_addr, 6);
				memcpy(&eth.dst_addr, mac_tmp, 6);
				//Swap IP addresses
				memcpy(ip_tmp, &ip.src_addr, 4);
				memcpy(&ip.src_addr, &ip.dst_addr, 4);
				memcpy(&ip.dst_addr, ip_tmp, 4);
				icmp._type = 3;
				icmp.code = 0;

				//Fill buffer and send
				push_icmp(icmp, ip, eth, buf, eth_size);
				printf("\nSending ICMP Error Message\n");
				send(active_socket, buf, n, 0);
				sent_flag = true;
				continue;
			}


			//Handle TTL

			//Decrement TTL
			printf("Decrementing ttl\n");
			ip.ttl--;
			if(ip.ttl <= 1){
				printf("Packet Dropped: Time Expired\n");
				//Send ICMP error message
				char mac_tmp[6];
				char ip_tmp[6];
				//Swapt HW addresses
				memcpy(mac_tmp, &eth.src_addr, 6);
				memcpy(&eth.src_addr, &eth.dst_addr, 6);
				memcpy(&eth.dst_addr, mac_tmp, 6);
				//Swap IP addresses
				memcpy(ip_tmp, &ip.src_addr, 4);
				memcpy(&ip.src_addr, &ip.dst_addr, 4);
				memcpy(&ip.dst_addr, ip_tmp, 4);
				icmp._type = 11;
				icmp.code = 0;

				//Fill buffer and send
				push_icmp(icmp, ip, eth, buf, eth_size);
				printf("\nSending ICMP Error Message\n");
				send(active_socket, buf, n, 0);
				sent_flag = true;
				continue;
			}
			else{

				//Fix checksum
				ip.checksum = 0;
				check = ip_calc_checksum(&ip, IP_HDR_LEN);
				ip.checksum = check;
			}


			icmp._type = 0;

			
			//Fill buffer and send
			push_icmp(icmp, ip, eth, buf, eth_size);
			printf("\nSending ICMP reply on %d\n", active_socket);
			send(active_socket, buf, n, 0);
		}

		
	}
	//Free allocated memory and exit
	free(router_ip0);
	free(router_ip1);
	free(router_ip2);
	free(router_ip3);
	return 0;
}