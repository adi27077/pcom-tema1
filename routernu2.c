#include "queue.h"
#include "skel.h"
#include "netinet/if_ether.h"

#define BUFLEN 100 /* lungimea unui segement citit din route table*/

// structura de tip intrare a tabelei de rutare
/*struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
};

// structura de tip intrare a tabelei arp
struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};*/

// functie de comparare a unor intrari din tabela de rutare, dupa prefix
// ajuta la quicksort
int cmp_prefix (const void * a, const void * b) {
   	return ((struct route_table_entry *)a)->prefix > 
		((struct route_table_entry*)b)->prefix;
}

// BONUS -- functie care calculeaza checksum dupa decrementarea ttl-ului
// returneaza noul checksum si actualizeaza ttl, conform RFC 1624
uint16_t ip_checksum_bonus(struct iphdr* iphdr){

	uint16_t old_field = iphdr->ttl;
	iphdr->ttl--;
	uint16_t new_field = iphdr->ttl;
	return iphdr->check - ~old_field - new_field - 1;
}

void build_ethhdr(struct ether_header *eth_hdr, uint8_t *sha, uint8_t *dha, unsigned short type)
{
	memcpy(eth_hdr->ether_dhost, dha, ETH_ALEN);
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	eth_hdr->ether_type = type;
}

void send_icmp(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface, int id, int seq)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
		.un.echo = {
			.id = id,
			.sequence = seq,
		}
	};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    packet.interface = interface;
	send_packet(&packet);
}

void send_icmp_error(uint32_t daddr, uint32_t saddr, uint8_t *sha, uint8_t *dha, u_int8_t type, u_int8_t code, int interface)
{

	struct ether_header eth_hdr;
	struct iphdr ip_hdr;
	struct icmphdr icmp_hdr = {
		.type = type,
		.code = code,
		.checksum = 0,
	};
	packet packet;
	void *payload;

	build_ethhdr(&eth_hdr, sha, dha, htons(ETHERTYPE_IP));
	/* No options */
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.check = ip_checksum(&ip_hdr, sizeof(struct iphdr));
	
	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr));

	payload = packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, &ip_hdr, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmp_hdr, sizeof(struct icmphdr));
	packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    packet.interface = interface;
	send_packet(&packet);
}

void send_arp(uint32_t daddr, uint32_t saddr, struct ether_header *eth_hdr, int interface, uint16_t ea_hdr)
{
	struct arp_header arp_hdr;
	packet packet;

	arp_hdr.htype = htons(ARPHRD_ETHER);
	arp_hdr.ptype = htons(2048);
	arp_hdr.op = ea_hdr;
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	memcpy(arp_hdr.sha, eth_hdr->ether_shost, 6);
	memcpy(arp_hdr.tha, eth_hdr->ether_dhost, 6);
	arp_hdr.spa = saddr;
	arp_hdr.tpa = daddr;
	memset(packet.payload, 0, 1600);
	memcpy(packet.payload, eth_hdr, sizeof(struct ethhdr));
	memcpy(packet.payload + sizeof(struct ethhdr), &arp_hdr, sizeof(struct arp_header));
	packet.len = sizeof(struct arp_header) + sizeof(struct ethhdr);
    packet.interface = interface;
	send_packet(&packet);
}

struct arp_header* parse_arp(void *buffer)
{
	struct arp_header *arp_hdr;
	struct ether_header *eth_hdr;

	eth_hdr = (struct ether_header *)buffer;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
		arp_hdr = (struct arp_header *)(buffer + sizeof(struct ether_header));
		return arp_hdr;
	} else
		return NULL;

}

struct icmphdr * parse_icmp(void *buffer)
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;

	eth_hdr = (struct ether_header *)buffer;
	if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
		ip_hdr = (struct iphdr *)(buffer + sizeof(struct ether_header));
			if (ip_hdr->protocol == 1) {
				struct icmphdr *icmp_hdr;
				icmp_hdr = (struct icmphdr *)(buffer + sizeof(struct iphdr) + sizeof(struct ether_header));
				return icmp_hdr;
			} else
				return NULL;


	} else
		return NULL;

}

// functie care parseaza tabela de rutare; returneaza prin efect lateral tabela
// de rutare, sortata dupa campul prefix, si prin efect direct dimensiunea
// tabelei
int parse_route_table(struct route_table_entry** r_table, char* file_name) {
	struct route_table_entry* route_table = NULL;
	FILE* input = fopen(file_name, "r");
	char buffer[BUFLEN];
	int k = 0;
	// citim din fisier, pe rand, campurile prefix, next hop, mask si interface
	while(fscanf(input, "%s", buffer) != -1) {
		k++;
		if(k == 1) {
			route_table = malloc(sizeof(struct route_table_entry));	
		}
		// folosim realloc pentru a nu folosi memorie in plus
		else {
			route_table = realloc(route_table, 
				k * sizeof(struct route_table_entry));
		}
		char n_hop[BUFLEN], msk[BUFLEN];
		struct route_table_entry aux;
		aux.prefix = inet_addr(buffer);
		fscanf(input, "%s", n_hop);
		aux.next_hop = inet_addr(n_hop);
		fscanf(input, "%s", msk);
		aux.mask = inet_addr(msk);
		fscanf(input, "%d", &(aux.interface));
		// adaugam la sfarsitul tabelei elementul curent
		route_table[k-1].prefix = aux.prefix;
		route_table[k-1].next_hop = aux.next_hop;
		route_table[k-1].mask = aux.mask;
		route_table[k-1].interface = aux.interface;
	}
	fclose(input);
	// la sfarsit, vom sorta tabela folosind algoritmul de qsort, deci cu o
	// complexitate de O(n*log n)
	qsort(route_table, k, sizeof(struct route_table_entry), cmp_prefix);
	*r_table = route_table;
	return k;
}

// functie care "updateaza" tabela arp, adica adauga in momentul in care se
// primeste un arp_reply, campurile specifice
// returneaza prin efect lateral tabela arp actualizata, iar prin efect direct
// noua lungime a tabelei
int update_arp_table(struct arp_entry** arp_table, uint32_t send_ip_addr,
		uint8_t* send_hw_addr, int arp_table_size) {
	struct arp_entry* arp_tbl;
	arp_tbl = *arp_table;
	arp_tbl = realloc(arp_tbl, (arp_table_size + 1) * sizeof(struct arp_entry));
	arp_tbl[arp_table_size].ip = send_ip_addr;
	memcpy(&arp_tbl[arp_table_size].mac, send_hw_addr, ETH_ALEN);

	*arp_table = arp_tbl;
	return ++arp_table_size;
}

// functie care gaseste in timp logaritmic, folosind cautare binara pe tabela
// deja sortata, cea mai buna ruta (deci complexitate de O(log n))
struct route_table_entry *get_best_route(uint32_t dest_ip, 
		struct route_table_entry* rtable, int rtable_size) {
	int begin = 0, end = rtable_size - 1;
	int mid = (begin + end) / 2;
	struct route_table_entry* result = &rtable[mid];
	while (begin <= end) {
		if (result->prefix < (dest_ip & result->mask)) {
			begin = mid + 1;
		}
		else if((dest_ip & result->mask) == result->prefix) {		
			return result;
		}
		else {
			end = mid - 1;
		}
		mid = (begin + end) / 2;
		result = &rtable[mid];
	}
	return NULL;
}


// Returneaza un pointer de tip struct arp_entry, catre campul din tabela arp care
// corespunde adresei ip cautate; daca nu exista acel ip in tabela, se va returna
// null
struct arp_entry *get_arp_entry(uint32_t ip, struct arp_entry* arp_table,
		int arp_table_len) {
	struct arp_entry* result = NULL;
	for(int i = 0; i < arp_table_len; i++) {
		if((ip ^ arp_table[i].ip) == 0) {
			result = &arp_table[i];
		}
	}
    return result;
}

// functie care trimite packetele aflate in coada, in momentul in care se
// primeste un arp reply
void send_packets_queue(queue* packets, packet m, struct ether_header* eth_hdr) {
	// cat timp coada mea nu este goala
	while (queue_empty(*packets) == 0) {
		// obtin noul packet de trimis
		packet* new_m = queue_deq(*packets);
		uint8_t router_mac[ETH_ALEN];
		struct ether_header * new_eth_hdr = (struct ether_header*)new_m->payload;
		new_eth_hdr->ether_type = htons(ETHERTYPE_IP);
		get_interface_mac(new_m->interface, router_mac);
		// ii actualizez ether_header-ul
		memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 
			ETH_ALEN * sizeof(uint8_t));
		memcpy(new_eth_hdr->ether_shost, router_mac, ETH_ALEN * sizeof(uint8_t));				
		// si dupa il trimit
        new_m->interface = m.interface;
		send_packet(new_m);
	}
}

// functie care face verificarile corespunzatoare in momentul in care s-a primit
// un packet arp, avand 2 posibilitati: REQUEST sau REPLY
void arp_rep_req(struct arp_header* arp_hdr, packet m, 
		struct ether_header* eth_hdr, struct iphdr* ip_hdr, int* arp_table_len,
		queue *packets, struct arp_entry** arp_table) {
	// is REQUEST
	if(htons(arp_hdr->op) == ARPOP_REQUEST) {
	uint8_t router_mac[ETH_ALEN];
	// salveaza in router_mac mac-ul router-ului
	get_interface_mac(m.interface, router_mac);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	// actualizeaza ether_header
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost,
		ETH_ALEN * sizeof(uint8_t));
	memcpy(eth_hdr->ether_shost, router_mac, ETH_ALEN * sizeof(uint8_t));
	// trimite un arp reply de confirmare hostului care a facut request
	send_arp(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
		eth_hdr, m.interface, htons(ARPOP_REPLY));				
	}
	// is REPLY
	else if(htons(arp_hdr->op) == ARPOP_REPLY) {
		// adauga in tabela arp adresa mac corespunzatoare ip-ului de la care 
		// s-a primit reply
		(*arp_table_len) = update_arp_table(arp_table, 
			arp_hdr->spa, arp_hdr->sha, *arp_table_len);
		// trimite packetele din coada catre hostul respectiv
		send_packets_queue(packets, m, eth_hdr);
	}
}

// functie care face verificarile in momentul in care se gaseste in tabela
// arp respectiva adresa, aka trimit direct packetul, fara a-l mai baga in coada
void arp_found(struct ether_header** eth_hdr, struct arp_entry* matching_arp,
		struct route_table_entry *best_route, packet* m) {
	memcpy((*eth_hdr)->ether_dhost, matching_arp->mac, 
		ETH_ALEN * sizeof(uint8_t));
	uint8_t router_mac[ETH_ALEN];
	get_interface_mac(best_route->interface, router_mac);
	memcpy((*eth_hdr)->ether_shost, router_mac, ETH_ALEN * sizeof(uint8_t));
	// trimiterea packetului, dupa actualizarea etherheaderului cu noua sursa
	// si noua destinatie
    m->interface = best_route->interface;
	send_packet(m);
	
}

// functie care trimite un arp request catre broadcast in momentul in care in
// tabela arp nu se gaseste ip-ul destinatie, pt a afla daca in retea se gaseste
// respectivul ip
void arp_not_found(struct ether_header** eth_hdr, 
		struct route_table_entry *best_route) {
	uint8_t router_mac[ETH_ALEN];
	(*eth_hdr)->ether_type = htons(ETHERTYPE_ARP);
	get_interface_mac(best_route->interface, router_mac);
	uint8_t broadcast_addr = 0xff;
	memcpy((*eth_hdr)->ether_shost, router_mac, ETH_ALEN * sizeof(uint8_t));
	memset((*eth_hdr)->ether_dhost, broadcast_addr, ETH_ALEN * sizeof(uint8_t));
	// se trimite un arp request catre broadcast
	send_arp(best_route->next_hop, 
		inet_addr(get_interface_ip(best_route->interface)), *eth_hdr, 
		best_route->interface, htons(ARPOP_REQUEST));
}

int main(int argc, char *argv[])
{
	// initializari date si structuri necesare "global"
	packet m;
	int rc;
	init(argc - 2, argv + 2);
	struct route_table_entry* route_table;
	// etapa de preprocesare a tabelei de rutare
	int route_table_len = parse_route_table(&route_table, argv[1]);
	struct arp_entry *arp_table = NULL;
	int arp_table_len = 0;
	queue packets = queue_create();
	
	while (1) {
		// receptionarea unui mesaj
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		// alte date care ne sunt necesare pe parcurs
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + 
			sizeof(struct ether_header));
		struct arp_header* arp_hdr = parse_arp(m.payload);
		struct icmphdr* icmp_hdr = parse_icmp(m.payload);
		// testarea primirii unui packet icmp
		if(icmp_hdr) {
			// daca acesta este icmp, si mai este si de tip echo request, atunci
			if(icmp_hdr->type == ICMP_ECHO) {
				// daca mesajul primit este destinat router-ului (adresa
				// destinatie este aceeasi cu adresa ip a router-ului)
				if(ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
					// atunci trimite un raspuns (packet icmp) de tip echo reply
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost,
						eth_hdr->ether_shost, ICMP_ECHOREPLY, 0, m.interface,
						icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
					continue;
				}
			}
		}
		// daca am primit un packet arp, atunci facem verificarile necesare;
		// pentru detalii, uramreste ce face functia arp_rep_req
		if(arp_hdr){
			arp_rep_req(arp_hdr, m, eth_hdr, ip_hdr, &arp_table_len,
						&packets, &arp_table);
			continue;
		}
		// calculeaza checksumul; daca este gresit, atunci nu il consideram
		uint16_t rez = ip_checksum(ip_hdr, sizeof(struct iphdr));
		if (rez == 0) {
			// daca checksum este ok, atunci verificam ttl
			if(ip_hdr->ttl > 1) {
				// daca ttl este ok, atunci calculam checksum si actualizam ttl
				// folosind bonusul, ip_checksum_bonus
				ip_hdr->check = ip_checksum_bonus(ip_hdr);
				// se cauta cea mai buna ruta din tabelul de rutare
				struct route_table_entry *best_route = get_best_route(
					ip_hdr->daddr, route_table, route_table_len
				);
				// daca nu se gaseste nicio ruta in tabela de rutare, atunci
				// vom trimite un mesaj eroare icmp, care ne spune ca packetul
				// nu a ajuns la destinatie
				if (best_route == NULL) {
					send_icmp_error(ip_hdr->saddr, ip_hdr->daddr,
						eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_UNREACH,
						ICMP_UNREACH_NET, m.interface);
					continue;
				}
				// se cauta in tabela arp adresa mac corespunzatoare adresei ip
				// la care vrem sa mergem
				struct arp_entry* matching_arp = get_arp_entry(
					best_route->next_hop, arp_table, arp_table_len
				);
				// daca o gasim, atunci trimite packetul
				if(matching_arp) {
					arp_found(&eth_hdr, matching_arp, best_route, &m);
				}
				// daca nu o gasim, atunci adaugam packetul in coada, si dam un
				// request la broadcast; pt mai multe detalii, vezi functiile de
				// mai sus
				else {
					packet copy_m;
					memcpy(&copy_m, &m, sizeof(packet));
					queue_enq(packets, &copy_m);
					arp_not_found(&eth_hdr, best_route);
				}
			}
			// daca ttl nu este bun, atunci vom trimite un mesaj de eroare catre
			// hostul de unde a venit packetul, mesaj de timpul time limit exceed
			else {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr,
					eth_hdr->ether_dhost,eth_hdr->ether_shost, ICMP_TIMXCEED, 
					ICMP_TIMXCEED_INTRANS, m.interface);
			}
		}
	}	
}