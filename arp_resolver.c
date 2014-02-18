/*
Chad Cahill
eece 555
Fall 2013
*/

/* Some of this code was provided by Dr. Kredo */
/* Some of this code came from getifaddr(3) */

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ifaddrs.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netpacket/packet.h>

int getMyAddresses(u_char *myMAC, u_char *myIPv4);

int getDstAddress(u_char *dstIPv4);

void genEthFrame(u_char *ethFrame, u_char *dstMAC, u_char *srcMAC, u_char *type);

void genARPpacket(u_char *ARPpacket, u_char *srcMAC, u_char *srcIPv4, u_char *dstMAC, u_char *dstIPv4);

void genEntirePacket(u_char *entirePacket, u_char *ethFrame, u_char *ARPpacket);

int isARPreply(const u_char *packet_data, u_char *myMAC, u_char *myIPv4, u_char *dstIPv4);

void printTargetMAC(const u_char *packet_data);

int main(int argc, char *argv[]) {
  u_char myMAC[6]; /* buffer to store my MAC address */
  u_char myIPv4[4]; /* buffer to store my IPv4 address */
  u_char dstIPv4[4]; /* buffer to store destination IPv4 address */
  u_char bcastMAC[6]; /* buffer to store broadcast MAC address */
  u_char type[2]; /* buffer to store type/length field for ethernet frame */
  u_char ethFrame[14]; /* buffer to store ethernet frame */
  u_char ARPpacket[28]; /* buffer to store ARP packet */
  u_char entirePacket[42]; /* buffer to store entire packet */

  char *dev_name = NULL; /* Device name for live capture */
  pcap_t *pcap_handle = NULL; /* Handle for PCAP library */
  char pcap_buff[PCAP_ERRBUF_SIZE]; /* Error buffer used by pcap functions */
  const u_char *packet_data = NULL; /* Packet data from PCAP */
  struct pcap_pkthdr *packet_hdr = NULL; /* Packet header from PCAP */
  int ret = 0; /* Return value from function calls */

  /* check command line arguments */
  if (argc > 2) {
    fprintf(stderr, "only enter a capture device\n");
    return -1;
  }
  else if (argc == 2) {
    dev_name = argv[1]; /* eth0 for example */
  }
  else {
    fprintf(stderr, "Specify a capture device\n");
    return -1;
  }

  /* Open the specified device */
  pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_buff);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
    return -1;
  }

  memset(bcastMAC, 0xFF, 6); /* Set broadcast MAC address (FF:FF:FF:FF:FF:FF) */

  type[0] = 0x08; /* ethernet type 0x0806 (ARP) for ethernet frame */
  type[1] = 0x06; 

  /* Lookup my MAC and IPv4 address */
  if (getMyAddresses(myMAC, myIPv4) == -1) {
    fprintf(stderr, "error from getMyAddresses\n");
    return -1;
  }

  while (1) {
    ret = getDstAddress(dstIPv4); /* Get target IPv4 address */
    if (ret == -1) {
      fprintf(stderr, "error from getDstAddress\n");
      return -1;
    }
    else if (ret == 1) { /* Exit program if no target IPv4 address is entered */
      break;
    }

    /* Generate ethernet frame */
    genEthFrame(ethFrame, bcastMAC, myMAC, type);

    /* Generate ARP packet */
    genARPpacket(ARPpacket, myMAC, myIPv4, bcastMAC, dstIPv4);

    /* Generate entire packet (put ethernet frame before ARP packet) */
    genEntirePacket(entirePacket, ethFrame, ARPpacket);

    /* Inject entire ARP request packet */
    if (pcap_inject(pcap_handle, entirePacket, 42) == -1) {
      fprintf(stderr, "error from pcap inject\n");
      return -1;
    }

    /* Look for appropriate ARP reply packet */
    ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
    int processed_packets = 0; /* integer used to count number of packets processed */
    while (1) {

      /* An error occurred */
      if (ret == -1) {
        pcap_perror(pcap_handle, "Error processing packet:");
        pcap_close(pcap_handle);
        return -1;
      }

      /* Unexpected return values */
      else if (ret != 1) {
        fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
        pcap_close(pcap_handle);
        return -1;
      }

      /* Process the packet */
      else {
        /* Check if the packet is an ARP reply 
         * from the targeted IPv4 address
         * destined for my MAC address 
         */
        if (isARPreply(packet_data, myMAC, myIPv4, dstIPv4) == 1) {
          /* ARP reply for me! */
          printTargetMAC(packet_data);
          break;
        }
        
        else if (processed_packets == 500) {
          /* 500 packets have been processed
           * with no ARP reply for me from 
           * the target MAC address
           */
          printf("MAC: Lookup failed\n");
          break;
        }
        processed_packets ++; 
      }

      /* Get the next packet */
      ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
    }
  }
  pcap_close(pcap_handle);
  return 0;
}

/* getMyAddresses() looks up this host's MAC and IPv4 addresses.
 * These addresses are stored in the MAC and IPv4 buffers given as arguments.
 * Returns 0 on success.
 * Returns -1 on error.
 */
int getMyAddresses(u_char *myMAC, u_char *myIPv4) {
  struct ifaddrs *ifaddr, *ifa;
  char IPv4[32];

  memset(myMAC, 0, 6);
  memset(myIPv4, 0, 4);

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return -1;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa-> ifa_next) {
    if (ifa -> ifa_addr == NULL)
      continue;

  if (ifa->ifa_addr->sa_family == AF_PACKET 
    && !(strcmp(ifa->ifa_name, "eth0"))) {
    // store my MAC address
    memcpy(myMAC, ((struct sockaddr_ll*)ifa->ifa_addr) -> sll_addr, 6);
  }

  if (ifa -> ifa_addr ->sa_family == AF_INET
    && !(strcmp(ifa -> ifa_name, "eth0"))) {
    // store my IPv4 address
    if (getnameinfo(ifa -> ifa_addr, sizeof(struct sockaddr_in), IPv4, 32,
      NULL, 0, NI_NUMERICHOST) != 0) {
      printf("getnameinfo() failed\n");
      return -1;
    }
    inet_pton(AF_INET, IPv4, myIPv4);
    }
  }
  return 0;
}

/* getDstAddress() asks the user to enter an IP address. 
 * An IPv4 address is then read in from standard input. 
 * The IPv4 address is stored in network byte order in the dstIPv4 buffer (argument).
 * Returns 0 on success.
 * Returns 1 when the user only presses enter (helps indicate to exit program).
 * Returns -1 when the user enters an invalid IPv4 address. 
 *  ~ Returns -1 on error (ie. read error).
 */
int getDstAddress(u_char *dstIPv4) {
  struct sockaddr_in sa;
  char IPv4[32];

  memset(dstIPv4, 0, 4);

  printf("Enter next IP address: ");
  if (fgets(IPv4, sizeof(IPv4), stdin) == NULL) {
    fprintf(stderr, "A read error has occured\n");
    return -1;
  }
  else if (*IPv4 == '\n') {
    return 1;
  }
  strtok(IPv4, "\n"); /* Remove newline character */

  /* Check if the entered address is a valid IPv4 address */
  if (inet_pton(AF_INET, IPv4, &(sa.sin_addr)) == 0) {
    fprintf(stderr, "Enter a valid ip address\n");
    return -1;
  }

  /* Convert to network byte order and store in destination IPv4 buffer */
  inet_pton(AF_INET, IPv4, dstIPv4);
  return 0;
}

/* genEthFrame() takes source and destination MAC addresses and type 
 * as arguments and stores them as an ethernet frame in the ethFrame buffer.
 */
void genEthFrame(u_char *ethFrame, u_char *dstMAC, u_char *srcMAC, u_char *type) {
  memcpy(ethFrame, dstMAC, 6);
  memcpy(ethFrame + 6, srcMAC, 6);
  memcpy(ethFrame + 12, type, 2);
  return;
}

/* genARPpacket() takes source and destination MAC and IPv4 addresses as arguments
 * and generates an ARP request packet with this information.
 */
void genARPpacket(u_char *ARPpacket, u_char *srcMAC, u_char *srcIPv4, u_char *dstMAC, u_char *dstIPv4) {
  char hardwareType[2];
  char protocolType[2];
  char HLen[1];
  char PLen[1];
  char operation[2];

  hardwareType[0] = 0x00; // hardware type is 0x0001 (eth0)
  hardwareType[1] = 0x01;

  protocolType[0] = 0x08; // protocol type is 0x0800 (IPv4)
  protocolType[1] = 0x00;

  HLen[0] = 6; // hardware length is 6 bytes (48 bits)

  PLen[0] = 4; // protocol length is 4 bytes (32 bits)

  operation[0] = 0x00; // operation is 0x0001 (request)
  operation[1] = 0x01;

  memcpy(ARPpacket, hardwareType, 2);
  memcpy(ARPpacket + 2, protocolType, 2);
  memcpy(ARPpacket + 4, HLen, 1);
  memcpy(ARPpacket + 5, PLen, 1);
  memcpy(ARPpacket + 6, operation, 2);
  memcpy(ARPpacket + 8, srcMAC, 6);
  memcpy(ARPpacket + 14, srcIPv4, 4);
  memcpy(ARPpacket + 18, dstMAC, 6);
  memcpy(ARPpacket + 24, dstIPv4, 4);

  return;
}

/* genEntirePacket() takes the ethernet frame and ARP packet as arguments and 
 * combines them to form a complete ARP request packet stored as the buffer
 * argument entirePacket.
 */
void genEntirePacket(u_char *entirePacket, u_char *ethFrame, u_char *ARPpacket) {
  memcpy(entirePacket, ethFrame, 14);
  memcpy(entirePacket + 14, ARPpacket, 28);
  return;
}

/* isARPreply() takes this host's IPv4 and MAC addresses as well as the target
 * IPv4 address from above as arguments. These are compared with the current 
 * packet's destination MAC address, and the current packet's source and destination
 * IPv4 addresses. 
 * Returns 1 if the current packet is an ARP reply from the targeted IPv4 address 
 * meant for this host. 
 * Else returns 0.
 */
int isARPreply(const u_char *packet_data, u_char *myMAC, u_char *myIPv4, u_char *dstIPv4) {
  if (
    memcmp(myMAC, packet_data, 6) == 0

    && memcmp(myIPv4, packet_data + 38, 4) == 0

    && memcmp(dstIPv4, packet_data + 28, 4) == 0
    ) {
    return 1;
  }
  return 0;
}

/* printTargetMAC() prints the source MAC address of the current packet. */
void printTargetMAC(const u_char *packet_data) {
  printf("MAC: ");
  printf("%02X:", packet_data[6]);
  printf("%02X:", packet_data[7]);
  printf("%02X:", packet_data[8]);
  printf("%02X:", packet_data[9]);
  printf("%02X:", packet_data[10]);
  printf("%02X", packet_data[11]);
  printf("\n");
  return;
}
