#include "queue.h"
#include "skel.h"

//Sets icmp header
void set_ether_header_icmp(struct ether_header *ethernet_header_icmp, struct ether_header *ethernet_header){
	memcpy(ethernet_header_icmp->ether_shost, ethernet_header->ether_dhost, ETH_ALEN); 
	memcpy(ethernet_header_icmp->ether_dhost, ethernet_header->ether_shost, ETH_ALEN);
	ethernet_header_icmp->ether_type = htons(ETHERTYPE_IP);
}

//Sets ip header for icmp
void set_ip_header_icmp(struct iphdr *ip_header_icmp, uint8_t tos, uint16_t tot_len, uint16_t id,
						uint16_t frag_off,uint8_t tll,uint8_t protocol,uint32_t saddr, uint32_t daddr){
	ip_header_icmp->tos = tos;
	ip_header_icmp->tot_len = tot_len;
	ip_header_icmp->id = id;
	ip_header_icmp->frag_off = frag_off;
	ip_header_icmp->ttl = tll;
	ip_header_icmp->protocol = protocol;
	ip_header_icmp->saddr = saddr;
	ip_header_icmp->daddr = daddr;
	ip_header_icmp->check = 0;
	ip_header_icmp->check = ip_checksum((uint8_t*)ip_header_icmp, sizeof(struct iphdr));
}

//Init icmp
void init_icmp(struct icmphdr *icmp_header, uint8_t code, uint8_t type, uint16_t id, uint16_t sequence){
	icmp_header->type = type;
	icmp_header->code = code;
	icmp_header->un.echo.id = id;
	icmp_header->un.echo.sequence = sequence;
	//Compute checksum
	icmp_header->checksum = 0;
	icmp_header->checksum = ip_checksum((uint8_t*)icmp_header, sizeof(struct icmphdr));
}

//Send icmp
void send_icmp (packet m, uint8_t type){
	packet new_icmp_packet;
	struct ether_header *ethernet_header = NULL;
	struct iphdr *ip_header = NULL;
	struct ether_header *ethernet_header_icmp;
	struct iphdr *ip_header_icmp;
	struct icmphdr *icmp_header;
	
	//Ethernet header of packet m
	ethernet_header = (struct ether_header *)m.payload;
	//Ip header of packet m
	ip_header = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	new_icmp_packet.interface = m.interface;
	memset(new_icmp_packet.payload, 0, sizeof(new_icmp_packet.payload));

	//Ethernet header of icmp packet
	ethernet_header_icmp = (struct ether_header *)new_icmp_packet.payload;
	//The ip header of the icmp packet
	ip_header_icmp = (struct iphdr *)(new_icmp_packet.payload + sizeof(struct ether_header));
	icmp_header = (struct icmphdr*)(new_icmp_packet.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
	new_icmp_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	
	//Ether Header
	//Sets icmp header
	set_ether_header_icmp(ethernet_header_icmp,ethernet_header);
	
	//INIT IPv4
	//Initializes the IPv4 header
	set_ip_header_icmp(ip_header_icmp,0,htons(sizeof(struct iphdr) + sizeof(struct icmphdr)),0,0,64,
					   IPPROTO_ICMP,inet_addr(get_interface_ip(m.interface)),ip_header->saddr);
	
	//INIT ICMP
	//Initializes the ICMP header
	init_icmp(icmp_header,0,type,0,0);

	//Send the icmp package
	send_packet(&new_icmp_packet);
}

//Find best route
struct route_table_entry* best_route(uint32_t destination_ip, struct route_table_entry *route_table_entries, 
									 int route_table_length){
	struct route_table_entry *result = NULL;
	int left_limit = 0;
	route_table_entries -= 1;

	//Binary search
	while(left_limit <= route_table_length){
		int middle = left_limit + (route_table_length - left_limit) / 2;

		//Found a match for nexthop
		if(route_table_entries[middle].prefix == (destination_ip & route_table_entries[middle].mask)){
			result = &route_table_entries[middle];
		}
		//Change the search range
		if(route_table_entries[middle].prefix > (destination_ip & route_table_entries[middle].mask)){
			left_limit = middle + 1;
		}else{
			route_table_length = middle - 1;
		}
	}
	return result;
}

//Get arp entry
struct arp_entry* get_arp_entry(uint32_t ip, struct arp_entry* arp_table, int len_arp_table){
	for(int i = 0; i < len_arp_table; i++){
		if(arp_table[i].ip == ip){
			return &arp_table[i];
		}
	}
	return NULL;
}

//Update checksum
void update_checksum(struct iphdr *ip_header, uint16_t tmp_checksum){
	ip_header->check = 0;		
	ip_header->ttl--;
	ip_header->check = tmp_checksum - ~((uint16_t)ip_header->ttl) - ((uint16_t)ip_header->ttl);
}

//Compare function for qsort
int compare_function(const void* el1, const void* el2){
	if((*(struct route_table_entry*)el1).prefix == (*(struct route_table_entry*)el2).prefix){
		return ((*(struct route_table_entry*)el2).mask - (*(struct route_table_entry*)el1).mask);
	}else{
		return ((*(struct route_table_entry*)el2).prefix - (*(struct route_table_entry*)el1).prefix);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	
	//Memory allocation for route_table
	struct route_table_entry* route_table = calloc(100000, sizeof(struct route_table_entry));
	int len_route_table = read_rtable(argv[1],route_table);
	qsort(route_table,len_route_table,sizeof(struct route_table_entry),compare_function);


	//Memory allocation for arp_table
	struct arp_entry* arp_table = calloc(100, sizeof(struct arp_entry));
	int len_arp_table = parse_arp_table("arp_table.txt",arp_table); 

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		struct ether_header *ether_header = (struct ether_header*) m.payload;
		struct iphdr *ip_header = (struct iphdr*)(m.payload + sizeof(struct ether_header));


		uint8_t routerMAC[ETH_ALEN];
		get_interface_mac(m.interface,routerMAC);
		uint8_t broadcast[ETH_ALEN];
		hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast);


		//Check if the packet is intended for the MAC address of the router
		if(memcmp(routerMAC,ether_header->ether_dhost, ETH_ALEN) != 0){
			//Check if it's broadcast
			if(memcmp(ether_header->ether_dhost, broadcast, ETH_ALEN) != 0){ 
				continue;
			}
		}
		printf("Pachetul este destinat routerului\n");
		

		//ARP type packet
		if(ether_header->ether_type == htons(ETHERTYPE_ARP)){
			//TODO:
			continue;
		}
		printf("Nu este pachet de tip ARP\n");


		uint32_t interfaceIP = inet_addr(get_interface_ip(m.interface));
		//ICMP type packet
		if(ether_header->ether_type == htons(ETHERTYPE_IP) && ip_header->protocol == IPPROTO_ICMP){
			if(interfaceIP == ip_header->daddr){
				//TODO:Echo reply
				send_icmp(m,0);
				continue;
			}
		}
		printf("Nu e pachet de tip ICMP\n");

		if(ether_header->ether_type != htons(ETHERTYPE_IP)) continue;

		//IPV4

		//Old checksum
		uint16_t tmp_checksum = ip_header->check;
		//Reset checksum from ip_header
		ip_header->check = 0;
		//Recalculate the checksum
		uint16_t new_checksum = ip_checksum((uint8_t*)ip_header,sizeof(struct iphdr));
		//If the old checksum is different from the calculated one
		if(new_checksum != tmp_checksum){
			continue;
		}
		printf("Checksum a fost calculat cu succes\n");
		

		//If tll has expired
		if(ip_header->ttl == 1 || ip_header->ttl == 0){
			//TODO:Time exceeded
			send_icmp(m, 11);
			continue;
		}
		printf("TLL nu a expirat\n");


		//Best route
		struct route_table_entry* bst_route = best_route(ip_header->daddr,route_table,len_route_table);
		if(bst_route == NULL){
			//TODO:Destination unreachable
			send_icmp(m,3);
			continue;
		}
		printf("A gasit best route\n");

		//Update checksum && dec tll
		update_checksum(ip_header,tmp_checksum);

		//arp_table entry
		struct arp_entry* arpFoud = get_arp_entry(bst_route->next_hop,arp_table,len_arp_table);
		//Update destination address
		memcpy(ether_header->ether_dhost,arpFoud->mac, ETH_ALEN);
		//Update source address
		memcpy(ether_header->ether_shost, ether_header->ether_dhost, ETH_ALEN);
		printf("A schimbat adresa sursa si adresa destinatie\n");
		
		//Send packet
		m.interface = bst_route->interface;
		send_packet(&m);
		printf("A TRIMIS PACHETUL\n");
	}
}