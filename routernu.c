#include "queue.h"
#include "skel.h"
#include <stdlib.h>
#include <string.h>

//tabela de rutare
//struct  route_table_entry *routeTable;
//dimensiune tabela de rutare
//int routeTableSize;
//coada pentru mesaje
queue q;


//tabela arp
struct arp_entry *arpTable;
//dimensiunea tabelei arp
int arpTableSize;


int cmpFunc(const void *a, const void *b)
{
    uint32_t pA = htonl(( (struct route_table_entry*) a)->prefix); //prefix prim elem
    uint32_t mA = htonl(( (struct route_table_entry*) a)->mask);//mask prim elem
    uint32_t pB = htonl(( (struct route_table_entry*) b)->prefix);//prefix 2-nd elem
    uint32_t mB = htonl(( (struct route_table_entry*) b)->mask);//mask 2-nd elem

    //Daca prefixele sunt egale
    if (pA == pB)
    {
        //verifica dupa mask
        return (int)(mB - mA);
        //daca nu sunt egale verifica dupa prefix
    } else return (int)(pA - pB);
}
//cautam best match arp
struct arp_entry *get_arp_entry(__u32 ip) {
    for (int i = 0; i < arpTableSize; ++i)
    {
        if (arpTable[i].ip == ip)
            return &arpTable[i];
    }
    return NULL;
}

/*void createRouteTable(char *filename)
{
    FILE *path;
    char line[64];
    path = fopen(filename,"r");

    //initializam tabela te rutare
    routeTable = malloc(sizeof(struct route_table) * 69420);

    /*citesc linie cu linie din fisier
     si initializez tabela de rutare
    int i = 0;
    char* token;
    // Citeste in path caracterul "\n" si muta pointerul din path catre urmatorul caracter
    while((fscanf(path, "%[^\n]",line)) != EOF){
        // pentru ca fscanf sa nu se opreasca din citit dupa ce a atins \n
        fgetc(path);
        token = strtok(line, " ");
        routeTable[i].prefix = inet_addr(token); //setez prefix-ul
        token = strtok(NULL, " ");
        routeTable[i].nextHop = inet_addr(token);//setez ip next hop-ului
        token = strtok(NULL, " ");
        routeTable[i].mask = inet_addr(token);//setez mask-ul
        token = strtok(NULL, " ");
        routeTable[i].interface = atoi(token);//setez nr interfetei;
        i++;
    }
    //dimensiune tabela
    routeTableSize = i;
}*/

struct route_table_entry *binarySearchHelper(struct route_table_entry *rtable, uint32_t dest_ip , int index) {
    //cauta adresa cu cel mai mare mask
    while((rtable[index - 1].prefix == rtable[index].prefix)
    && (index > 0 )){
        index--;
    }
    return rtable + index;
}

struct route_table_entry *binarySearch(struct route_table_entry *rtable, int left, int right, uint32_t dest_ip) {

    while (right >= left)
    {
        int middle = left + (right - left) / 2;
        //verifica daca coincide adresa cautata cu o adresa din tabel
        if((rtable[middle].mask & dest_ip) == rtable[middle].prefix) {
            //verifica daca mai exista adrese care coincid si alege pe cea cu mask-a mai mare
            return binarySearchHelper(rtable, htonl(dest_ip), middle);
            //typical binarySearch logic
        } else if((htonl(rtable[middle].mask) & htonl(dest_ip)) > htonl(rtable[middle].prefix)) {
            return binarySearch(rtable, middle + 1, right, dest_ip);
        } else {
            return binarySearch(rtable, left, middle - 1, dest_ip);
        }
    }
    return NULL;
};

void sendRequest(uint32_t dest_ip, int interface) {
    //creaza un packet
    packet *reply= calloc(1, sizeof(packet));
    reply->interface = interface;
    reply->len = (sizeof(struct ether_arp) + sizeof(struct ether_header));

    struct ether_arp * pEtherArp = (struct ether_arp*)(reply->payload + sizeof(struct ether_header));
    struct ether_header * eth_hdr = (struct ether_header *)reply->payload;

    //setam adresa de broadcast 255.255.255.255
    for (int i = 0; i < 6; ++i) {
        pEtherArp->arp_tha[i] = 0xff;
    }
    get_interface_mac(interface, pEtherArp->arp_sha);
    char *ip_s = get_interface_ip(interface);
    struct in_addr ip ;
    inet_aton(ip_s, &ip);
    memcpy(&(pEtherArp->arp_spa), &(ip.s_addr), 4);

    //set ethernet header
    get_interface_mac(interface, eth_hdr->ether_shost);
    for (int i = 0; i < 6; ++i) {
        eth_hdr->ether_dhost[i] = 0xff;
    }
    //setez campurile de arp
    pEtherArp->ea_hdr.ar_hln = 6;
    //tipul pachetului
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    //tip op cod reply/request
    pEtherArp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    //tip ethernet ip
    pEtherArp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    //dimensiune adresa mac
    pEtherArp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    //copiez adresa ip
    memcpy(&(pEtherArp->arp_tpa), &(dest_ip), 4);
    //dimensiune adresa ip
    pEtherArp->ea_hdr.ar_pln = 4;
    //trimit mesajul
    send_packet(reply);

};

void arpRequest(packet *m)
{

    struct ether_arp * pEtherArp = (struct ether_arp*)  (m->payload + sizeof(struct ether_header));
    struct ether_header * eth_hdr = (struct ether_header *) m->payload;

    //inversem adresele in headerul ethernel
    memcpy(&(eth_hdr->ether_dhost), &(eth_hdr->ether_shost), 6);
    get_interface_mac(m->interface, eth_hdr->ether_shost);

    int sp;
    memcpy(&(sp), &(pEtherArp->arp_tpa), 4);
    //inversam adresele de protocol header arp
    memcpy(&(pEtherArp->arp_tpa), &(pEtherArp->arp_spa), 4);
    memcpy(&(pEtherArp->arp_spa), &(sp), 4);

    //setam adresele mac in header-ul arp
    memcpy(&(pEtherArp->arp_tha), &(eth_hdr->ether_dhost), 6);
    memcpy(&(pEtherArp->arp_sha), &(eth_hdr->ether_shost), 6);

    pEtherArp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    send_packet(m);



};
void arpReply(packet *m){

    //adaugam in tabela ARP ip si mac primit in urma unui ArpReply
    struct ether_arp * pEtherArp = (struct ether_arp*) (m->payload + sizeof(struct ether_header));
    memcpy(&(arpTable[arpTableSize].ip), &(pEtherArp->arp_spa), 4);
    memcpy(&(arpTable[arpTableSize].mac), &(pEtherArp->arp_sha), 6);
    //updatam dimensiunea tabelei
    arpTableSize++;

};


void icmpChecker(packet *m, uint8_t type) {
    //cream un packet nou pentru a trimite ca raspuns
    packet *reply = calloc(1, sizeof (packet));
    //copiem din mesajul initial in packet-ul de reply
    memcpy(&(reply->payload), &(m->payload), m->len);
    //setam dimensiunea packetu-ului
    reply->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    //setam interfata
    reply->interface = m->interface;

    struct ether_header * eth_hdr = (struct ether_header *) reply->payload;
    struct iphdr *ip_hdr = (struct iphdr *) (reply->payload + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *) (reply->payload +sizeof(struct ether_header)
            + sizeof(struct iphdr));

    //aflam adresa interfetei
    char *ip_s = get_interface_ip(m->interface);
    struct in_addr ip ;
    inet_aton(ip_s, &ip);

    //setam header-ul icmp
    icmp_hdr->type = type;
    icmp_hdr->checksum = 0;
    //recalculam checksum
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(m->payload - sizeof(struct ether_header) - sizeof(struct iphdr)));

    // inversam adresele ip
    memcpy(&(ip_hdr->daddr), &(ip_hdr->saddr), 4);
    memcpy(&(ip_hdr->saddr), &(ip.s_addr), 4);

    //setam header-ul ip
    ip_hdr->ttl = 69;
    ip_hdr->version = 4;
    //setam dimensiunea
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->id = getpid();
    //setam tipul de protocol
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->ihl = 5;
    ip_hdr->check = 0;
    //recalculam checksum
    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));


    memcpy(&(eth_hdr->ether_dhost), &(eth_hdr->ether_shost), 6);
    get_interface_mac(m->interface, eth_hdr->ether_shost);

    //Trimitem packet-ul de raspuns
    send_packet(reply);
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Citim tabela de rutare
    struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rtsize = read_rtable(argv[1], rtable);
    // Citim tabela arp
    //createArpTable();
    //arpTable = malloc(sizeof(struct arpEntry) * 12);
    //arpTableSize = 0;
    //sortare table O(n log n)
    qsort(rtable, rtsize, sizeof(struct route_table_entry),cmpFunc);

    q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
        struct ether_arp *arp_hdr = (struct ether_arp *) (m.payload + sizeof(struct ether_header));
        struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
        struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header)+ sizeof(struct iphdr));

        //verificam daca este un packet arp
        if (htons(eth_hdr->ether_type) == ETHERTYPE_ARP)
        {
            //verificam daca este un arp reply
            if(arp_hdr->ea_hdr.ar_op == htons(ARPOP_REPLY))
            {
                arpReply(&m);
                //trimite mesaje daca sunt in coada de asteptare
                while(!queue_empty(q)) {
                    //scoatem din coada mesaj
                	packet *end = (packet*)queue_deq(q);
                    struct iphdr *ipH = (struct iphdr *)(end->payload + sizeof(struct ether_header));
                    struct ether_header *pEther = (struct ether_header *)end->payload;

                    //decrementam ttl-ul
                    ipH->ttl--;
                    //gasim next ho
                    struct route_table_entry *n = binarySearch(rtable, 0, rtsize, ipH->daddr);
                    //calculam checksum-ul
                    ipH->check = 0;
                    ipH->check = ip_checksum(ipH, sizeof(struct iphdr));
                    //gasim adresa de nexthop
                    struct arp_entry *e = get_arp_entry(n->next_hop);
                    //gasim adresa mac
                    get_interface_mac(n->interface, pEther->ether_shost);
                    //setam adresa mac a next hop-ului
                    memcpy(pEther->ether_dhost, e->mac, sizeof(e->mac));

                    //trimitem pachetul
                    send_packet(end);

                }
            continue;
            }
            //verificam daca este un arp request
            if(arp_hdr->ea_hdr.ar_op == htons(ARPOP_REQUEST))
            {
                arpRequest(&m);
                continue;
            }

        }
        //verificam daca este un packet ip
        if(htons(eth_hdr->ether_type) == ETHERTYPE_IP) {
            //salvez valoarea checksum-ului veche
            uint16_t oldChecksum = ip_hdr->check;
            ip_hdr->check = 0;
            //calculez noul checksum
            uint16_t newChecksum = ip_checksum(ip_hdr, sizeof(struct iphdr));
            //verificam checksum-ul
            if (oldChecksum != newChecksum) {
                //drop la paket
                continue;
            }
            //verificam daca nu este ttl < 1
            if (ip_hdr->ttl <= 1) {
                //Trimitem un packet icmp_time_exceeded
                icmpChecker(&m, ICMP_TIME_EXCEEDED);
                //drop la pachet
                continue;
            }
            struct route_table_entry *next = binarySearch(rtable, 0, rtsize, ip_hdr->daddr);
            //Verificam daca am gasit adresa in tabel
            if (next == NULL) {
                //trimitem un paket icmp_dest_unreachable
                icmpChecker(&m, ICMP_DEST_UNREACH);
                //drop la packet
                continue;;
            }
            //alfam ip-ul interfetei
            char *ip = get_interface_ip(m.interface);
            struct in_addr int_ip;
            inet_aton(ip, &int_ip);

            if (ip_hdr->daddr == int_ip.s_addr) {
                /*verificam daca adresa ping-ului este adresa interfetei
                de pe care am trimis */
                if (ip_hdr->protocol == IPPROTO_ICMP) {
                    //verificam daca este un paket ICMP
                    if (icmp_hdr->type == ICMP_ECHO) {
                        //verificam daca este un paket ICMP de tipul ECHO_REPLYY
                        icmpChecker(&m, ICMP_ECHOREPLY);
                    }
                }
                //drop la packet
                continue;
            }

            //Cautam in next hop-ul in tabela
            struct arp_entry *entry = get_arp_entry(next->next_hop);
            //Verificam daca avem un entry valid
            if (entry == NULL) {
                //cream copie packet
                packet * r = calloc (1, sizeof(packet));
                memcpy(r->payload, m.payload, m.len);
                r->len = m.len;
                r->interface = m.interface;
                //punem in coada mesajul
                queue_enq(q, r);
                //trimitem un arp request
                sendRequest(next->next_hop, next->interface);
                continue;
            }
            //decrementam ttl-ul
            ip_hdr->ttl--;
            //recalculam checksum-ul
            ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
            //aflam adresa mac a bestroute-ului
            get_interface_mac(next->interface, eth_hdr->ether_shost);
            //setam adresa mac a next hop-ului
            memcpy(eth_hdr->ether_dhost, entry->mac, sizeof(entry->mac));
			m.interface = next->interface;
            //trimitem pachetul
            send_packet(&m);
		}
	}
}
