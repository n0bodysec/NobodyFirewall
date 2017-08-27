/***********************************
 *         Nobody Firewall         *
 *                                 *
 *   @Author:    Nobody            *
 *   @Version:   0.1 BETA FIX #2   *
 *   @Date:      26/08/2017        *
 *                                 *
 * Thanks to Silver Moon & n3ptun0 *
 **********************************/

/* ==================================== [ INCLUDES ] ==================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pthread.h>

/* ==================================== [ DEFINES ] ==================================== */
//#define FLAG_DEBUG
#define	FIREWALL_VERSION "0.1 BETA"
#define SLEEP_SECONDS	 (1)
#define MAX_QUERIES		 (60) // per SLEEP_SECONDS
#define MAX_COOKIES		 (5) // per SLEEP_SECONDS
#define	STRUCT_NUMBER	 (700)

typedef unsigned int uint;
void ProcessPackets(u_char*, const struct pcap_pkthdr*, const u_char*);
void ProcessUDPPacket(const u_char*, int);
void ProcessSAMPPacket(char* host, u_short port, u_short dst_port, uint query);
void ProcessCookiePacket(char* host, u_short port, u_short dst_port);
void* threadCheck(void* ptr);
void threadReload();
void Ban(char* host, u_short port, u_short dst_port, int type);
int CheckIfExists(char* host);

struct userPackets
{
	char host[30];
	long int CookiePackets;
	long int QueryPackets;
};
struct userPackets ddosInfo[STRUCT_NUMBER];

struct sockaddr_in source, dest;

FILE* logfile;
time_t _rw;
struct tm *tm;

/* ==================================== [ FUNCTIONS ] ==================================== */
int main(int argc, char* argv[])
{
	threadReload();
	pthread_t thread1;
	pthread_create(&thread1, NULL, threadCheck, NULL);
	
	pcap_if_t *alldevsp;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// get interface
	char* iface;
	if (!argv[1])
	{
		FILE* f = fopen("/proc/net/route", "r");
		char line[100];
		while (fgets(line, 100, f))
		{
			char* p = strtok(line, " \t"); char* c = strtok(NULL, " \t");
			if ((p != NULL && c != NULL) && (strcmp(c, "00000000") == 0))
			{
				iface = p;
				break;
			}
		}
	}
	else iface = argv[1];
	
	system("clear");
	printf("######################################################\n");
	printf("#         Nobody Firewall v"FIREWALL_VERSION" started.         #\n");
	printf("######################################################\n");
	if (argc < 2) printf("[!] Usage: %s <iface>\n", argv[0]);
#ifdef FLAG_DEBUG
	printf("[!] Information: Debug flag is enabled.\n");
#endif
	if (!argv[1])
		printf("[!] Warning: Using default interface: \"%s\".\n\n", iface);
	
	printf("[!] Finding available devices, please wait...");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		printf("\n[!] Error finding devices: %s\n", errbuf);
		exit(1);
	}
	printf(" Done.\n");
	
	printf("[!] Opening device \"%s\" for sniffing...", iface);
	handle = pcap_open_live(iface, 65536, 1, 0, errbuf);
	
	if (handle == NULL)
	{
		printf("\n[!] Couldn't open device \"%s\": %s\n", iface, errbuf);
		exit(1);
	}
	printf(" Done.\n");
	
	pcap_setdirection(handle, PCAP_D_IN);
	pcap_loop(handle, -1, ProcessPackets, NULL);
	return 0;
}

void ProcessPackets(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol)
	{
		case 17: // UDP Protocol
			ProcessUDPPacket(buffer, header->len);
			break;
			
		default: break;
	}
	//printf("Logging packets...\r");
}

void ProcessUDPPacket(const u_char* buffer, int size)
{
	unsigned short iphdrlen;
	
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	struct udphdr* udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	const u_char* packet = buffer + header_size;
	
	if ((uint)packet[0] == 0x53 && (uint)packet[1] == 0x41 && (uint)packet[2] == 0x4d && (uint)packet[3] == 0x50)
		ProcessSAMPPacket(inet_ntoa(source.sin_addr), ntohs(udph->source), ntohs(udph->dest), (uint)packet[10]);
		
	if ((uint)packet[0] == 0x08 && (uint)packet[1] == 0x1e /* && (uint)packet[2] == 0x?? */ && (uint)packet[3] == 0xda)
		ProcessCookiePacket(inet_ntoa(source.sin_addr), ntohs(udph->source), ntohs(udph->dest));
		
/*#ifdef FLAG_DEBUG
	if ((uint)packet[0] == 0x28 && ntohs(udph->len) == 12) // incoming connection
		printf("[!] Incoming connection packet from %s.\n", inet_ntoa(source.sin_addr));
#endif*/
}

void ProcessSAMPPacket(char* host, u_short port, u_short dst_port, uint query)
{
#ifdef FLAG_DEBUG
	printf("[!] Incoming query:%c packet from %s:%d to port %d.\n", query, host, port, dst_port);
#endif
	int check = CheckIfExists(host);
	if (check != -1)
	{
		ddosInfo[check].QueryPackets++;
		if (ddosInfo[check].QueryPackets > MAX_QUERIES)
			Ban(ddosInfo[check].host, 1, port, dst_port);
	}
	else
	{
		int i = 0;
		for (i = 0; i < STRUCT_NUMBER; i++)
		{
			if (strcmp(ddosInfo[i].host, "127.0.0.1") == 0)
			{
				strcpy(ddosInfo[i].host, host);
				ddosInfo[i].QueryPackets += 1;
				break;
			}
		}
	}
}

void ProcessCookiePacket(char* host, u_short port, u_short dst_port)
{
#ifdef FLAG_DEBUG
	printf("[!] Incoming cookie packet from %s:%d to port %d.\n", host, port, dst_port);
#endif
	int check = CheckIfExists(host);
	if (check != -1)
	{
		ddosInfo[check].CookiePackets++;
		if (ddosInfo[check].CookiePackets > MAX_COOKIES)
			Ban(ddosInfo[check].host, 0, port, dst_port);
	}
	else
	{
		int i = 0;
		for (i = 0; i < STRUCT_NUMBER; i++)
		{
			if (strcmp(ddosInfo[i].host, "127.0.0.1") == 0)
			{
				strcpy(ddosInfo[i].host, host);
				ddosInfo[i].CookiePackets += 1;
				break;
			}
		}
	}
}

void Ban(char* host, u_short port, u_short dst_port, int type)
{
	static char buffer[85];
	sprintf(buffer, "Incoming attack from %s:%d to port %d. Attack type: %s. Blocking it.\n", host, port, dst_port, (type == 1 ? "Query Flood" : "Cookie Flood"));
	printf("[!] %s", buffer);
	time(&_rw);
	tm = localtime(&_rw);
	if ((logfile = fopen("nfwall.txt", "a")) == NULL)
		printf("[!] Unable to open log file.\n");
	fprintf(logfile, "[%02d/%02d/%02d - %02d:%02d:%02d] %s", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, buffer);
	fclose(logfile);
	char cmd[50];
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "iptables -A INPUT -s %s -j DROP", host);
	system(cmd);
}

int CheckIfExists(char* host)
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		if (strcmp(ddosInfo[i].host, host) == 0)
		return i;
	}
	return -1;
}

void threadReload()
{
	int i = 0;
	for (i = 0; i < STRUCT_NUMBER; i++)
	{
		strcpy(ddosInfo[i].host, "127.0.0.1");
		ddosInfo[i].CookiePackets = 0;
		ddosInfo[i].QueryPackets = 0;
	}
}

void* threadCheck(void* ptr)
{
	while (1)
	{
		sleep(SLEEP_SECONDS);
		threadReload();
	}
}