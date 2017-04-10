#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <err.h>

#define BUF_SIZE 1000

#define SRC_IP "10.145.37.119"

using namespace std;

uint16_t compute_checksum (uint16_t *buf, int hdr_len)    //function to compute checksum
{
    uint16_t sum;
    for (sum = 0; hdr_len > 0; hdr_len--)
      	sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char const *argv[])
{
	if(argc != 2)
	{
		cout<<"Usage Error : ./traceroute <Domain name or IPv4 address>\n";
		return 0;
	}

	int i, hostflag = 0;
  for(i=0; i<strlen(argv[1]); i++)    //checking if the the 2nd parameter is domain name or IPv4 address
  {
  	if(argv[1][i] != '.')
  	{
  		if(argv[1][i]-'0' > 9)
  			hostflag = 1;
  	}
  }

	char buffer[BUF_SIZE];
	memset(buffer, 0, BUF_SIZE);
	char address[BUF_SIZE];
	char hostname[BUF_SIZE];

	if(hostflag == 1)		//hostname given in input -> do forward lookup
	{
		struct hostent* HostInfo;

		strcpy(hostname, argv[1]);
		HostInfo=gethostbyname(argv[1]);

		if(!HostInfo)
		{
		    cout<<argv[1]<<": Name or service not known.\n";
		    return 0;
		}

		strcpy(address, inet_ntoa(*(struct in_addr *)(HostInfo->h_addr)));
		//cout<<address << endl;
	}
	else		//IPv4 address given in input -> do reverse lookup to get domain name
	{
		strcpy(address, argv[1]);
		struct in_addr ip;
		struct hostent *hp;

		if (!inet_aton(argv[1], &ip))
    {
		    errx(1, "can't parse IP address %s", argv[1]);
    }

		if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)
    {
			strcpy(hostname, argv[1]);
    }
		else
    {
			strcpy(hostname, hp->h_name);
    }
	}
  bzero(buffer, BUF_SIZE);
	struct ip *ip_hdr = (struct ip *) buffer;

	struct sockaddr_in sin, din;

	int sd;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);	//create raw socket

	if(sd < 0)
	{
		perror("socket() error");
    exit(EXIT_FAILURE);
	}
	//else printf("socket() - Using SOCK_RAW socket is OK.\n");

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(SRC_IP);

	din.sin_addr.s_addr = inet_addr(address);
	din.sin_port = 0;
	din.sin_family = AF_INET;

	unsigned int fromlen = sizeof(din);

	int no_hops = 1;
  int ttl = 1;

	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &ttl, sizeof(ttl)) < 0)
  {
  	perror("setsockopt error : ");
  	exit(EXIT_FAILURE);
  }

  cout<<"traceroute to "<<hostname<<" ("<<address<<"), 30 hops max, "<<sizeof(struct ip) + sizeof(struct icmphdr) <<" bytes of packet\n";
  while(1)
  {
    char recv[BUF_SIZE];
		bzero(recv, BUF_SIZE);
		double rtt[3];
		struct sockaddr_in d_router;
		socklen_t len_router = sizeof(struct sockaddr_in);

		ip_hdr->ip_hl = 5;  //header length
    ip_hdr->ip_v = 4;   //IP version
    ip_hdr->ip_off = 0;   //fragment offset
    ip_hdr->ip_ttl = no_hops;   //time to live
    ip_hdr->ip_p = IPPROTO_ICMP;    //protocol
    ip_hdr->ip_tos = 0;   //type of service (differentiated service)
    ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct icmphdr);   //total length of packet
    ip_hdr->ip_id = 1000;  //identification
    ip_hdr->ip_sum = compute_checksum((uint16_t *) buffer, 20);   //header checksum computed

  	inet_pton (AF_INET, SRC_IP, &(ip_hdr->ip_src));     //source IP
    inet_pton (AF_INET, address, &(ip_hdr->ip_dst));    //destination IP

		struct icmphdr *icmp = (struct icmphdr*)(buffer + 20);    //IP header size = 20 bytes

		icmp->code = 0; //further qualifies the ICMP message
		icmp->type = ICMP_ECHO;   //ICMP_ECHO -> 8 (actually depends upon the type of packet)
		icmp->checksum = 0;
		icmp->un.echo.sequence = no_hops + 1;   //helps to match echo requests with the associated reply
		icmp->un.echo.id = 0;    //helps to match echo requests with the associated reply
		icmp->checksum = compute_checksum((uint16_t *) (buffer + 20), 8);   //header checksum

		int rtt_valid = 0;

		for(i=0; i<3; i++)
		{
			struct timeval tv1, tv2;
			gettimeofday(&tv1, NULL);

			if(sendto(sd, buffer, sizeof(buffer), 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)		//icmp ECHO REQUEST packet sending
			{
				perror("Sendto error : ");
        exit(EXIT_FAILURE);
			}

			fd_set read;
			FD_ZERO(&read);
			FD_SET(sd, &read);

      struct timeval s2;    //2 second timeout
      s2.tv_sec = 2;
	    s2.tv_usec = 0;

	    int scan_activity;
			scan_activity = select(101, &read, NULL, NULL, &s2);

			if(FD_ISSET(sd, &read))
			{
				if(recvfrom(sd, recv, sizeof(recv), 0, (struct sockaddr*)&d_router, &len_router) < 0)
				{
					perror("recvfrom error : ");
				}
				gettimeofday(&tv2, NULL);
				rtt[i] = (tv2.tv_sec-tv1.tv_sec)*1000 + (tv2.tv_usec-tv1.tv_usec)/1000.0;
			}
			else
			{
				rtt_valid++;
			}
		}

		struct icmphdr *rec_icmp = (struct icmphdr*)(recv + 20);

		if(rec_icmp->type == 3)     //ERROR case -> destination unreachable or doesn't exist or admin lock
		{
			char host[1024];
			char service[20];

			struct sockaddr_in sa;
			inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

			int res = getnameinfo((struct sockaddr*)&sa, sizeof(struct sockaddr_in), host, sizeof host, service, sizeof service, 0);   //reverse DNS lookup of sender router

			cout<<" "<<no_hops<<"  ";
			if(res)
				cout<<inet_ntoa(d_router.sin_addr);
			else
				cout<<host;
			if(rec_icmp->code == 1)
				cout<<"  (" << inet_ntoa(d_router.sin_addr) <<")  "<<rtt[0]<<" ms  !H "<<rtt[1]<<" ms  !H "<<rtt[2]<<" ms !H"<<endl;		//host unreachable
			else if(rec_icmp->code == 10)
				cout<<"  (" << inet_ntoa(d_router.sin_addr) <<")  "<<rtt[0]<<" ms  !X "<<rtt[1]<<" ms  !X "<<rtt[2]<<" ms !X"<<endl;		//prohibited
			else if(rec_icmp->code == 3)
				cout<<"  (" << inet_ntoa(d_router.sin_addr) <<")  "<<rtt[0]<<" ms  !U "<<rtt[1]<<" ms  !U "<<rtt[2]<<" ms !U"<<endl;	//port unreachable

			return 0;
		}
		else if(rtt_valid >= 1)    //router unresponsive
		{
			cout<<" "<<no_hops<<"  * * *\n";
		}
		else if(rec_icmp->type == 11)   //ICMP TTL exceeded packet received
		{
			char host[1024];
			char service[20];

			struct sockaddr_in sa;
			inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

			int res = getnameinfo((struct sockaddr*)&sa, sizeof(struct sockaddr_in), host, sizeof host, service, sizeof service, 0);

			cout<<" "<<no_hops<<"  ";
			if(res)
				cout<<inet_ntoa(d_router.sin_addr);
			else
				cout<<host;
			cout<<"  (" << inet_ntoa(d_router.sin_addr) <<")  "<<rtt[0]<<" ms  "<<rtt[1]<<" ms  "<<rtt[2]<<" ms"<<endl;
		}
		else if(rec_icmp->type == 0)    //ECHO REPLY received -> destination found
		{
			char host[1024];
			char service[20];

			struct sockaddr_in sa;
			sa.sin_family = AF_INET;
			inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

			int res = getnameinfo((struct sockaddr*)&sa, sizeof(struct sockaddr_in), host, sizeof host, service, sizeof service, 0);

			cout<<" "<<no_hops<<"  ";
			if(res)
				cout<<inet_ntoa(d_router.sin_addr);
			else
				cout<<host;
			cout<<"  (" << inet_ntoa(d_router.sin_addr) <<")  "<<rtt[0]<<" ms  "<<rtt[1]<<" ms  "<<rtt[2]<<" ms"<<endl;
			//cout<<"Reached Destination : "<<inet_ntoa(d_router.sin_addr)<<" with hop limit"<<no_hops<<endl;
			return 0;
		}
		if(no_hops < 30)
			no_hops++;
		else
			return 0;
  }
	return 0;
}
