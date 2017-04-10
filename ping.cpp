

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
#include <signal.h>
#include <cmath>

#define BUF_SIZE 10000
#define MAX_TRIES 100

using namespace std;

int packets_sent = 0;
int packets_recv = 0;
double rtt[MAX_TRIES] = {0.0};

char buffer[BUF_SIZE];
char address[BUF_SIZE];
char hostname[BUF_SIZE];

double global_start_time, global_end_time;

//8 byte custom icmp header
typedef struct icmph
{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union
	{
  	struct
  	{
    		u_int16_t	id;
    		u_int16_t	sequence;
  	} echo;			/* echo datagram */
	}un;
}icmph;

//standard checksum function
unsigned short compute_checksum (unsigned short *buf, int nwords)
{
  	unsigned long sum;
  	for (sum = 0; nwords > 0; nwords--)
    	sum += *buf++;
  	sum = (sum >> 16) + (sum & 0xffff);
  	sum += (sum >> 16);
  	return ~sum;
}

//signal handler for showing statistics
int error_no;

void sig_handler(int signal)
{
	struct timeval tv3;
	gettimeofday(&tv3, NULL);
	global_end_time = (tv3.tv_sec)*1000 + (tv3.tv_usec)/1000.0;

	cout<<"--------"<<hostname<<" ping statistics-----------\n";
	packets_recv -= error_no;

	cout<<packets_sent<<" packets transmitted"<<", "<<packets_recv <<" packets received";

	if(error_no > 0)
		cout<<", +"<<error_no<<" errors";

	double lost = ((packets_sent - packets_recv)/(double)packets_sent)*100;

	cout<<", "<<(int)lost<<"% packet loss, time="<<(global_end_time - global_start_time)<<" ms"<<endl;		//calculate time here

	double avg = 0.0, min = rtt[0], max = 0.0;

	for(int i=0; i<packets_recv ; i++)
	{
		avg = avg + rtt[i];
		if(rtt[i] > max)
			max = rtt[i];
		if(rtt[i] < min)
			min = rtt[i];
	}
	avg = avg / (double)packets_recv;

	double mdev = 0.00;
	for(int i=0; i<packets_recv; i++)
	{
		if(rtt[i] - avg >= 0)
			mdev = mdev + (double)(rtt[i] - avg);
		else
			mdev = mdev + (double)(avg - rtt[i]);
	}
	mdev /= (double)packets_recv;
	if(packets_recv > 0 && error_no == 0)
		cout<<"rtt min/avg/max/mdev = "<<min<<"/"<<avg<<"/"<<max<<"/"<<mdev<<" ms"<<endl;
	exit(0);
}

int msgsz;
int count ;

int main(int argc, char const *argv[])
{
	bzero(buffer, BUF_SIZE);
	memset(buffer, 0, BUF_SIZE);
	count = 0;

	struct timeval tv3;
	gettimeofday(&tv3, NULL);
	global_start_time = (tv3.tv_sec)*1000 + (tv3.tv_usec)/1000.0;

	if(argc < 2 || argc >3)
	{
		cout<<"Usage Error : ./ping <Domain name or IPv4 address> <optional-payload>\n";
		exit(EXIT_FAILURE);
	}

	if(argc == 3)
	{
		msgsz = atoi(argv[2]);
	}
	else if(argc == 2)
	{
		msgsz = 56;			//default payload value
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

	struct sockaddr_in sin, din;

	int sd;
	sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);				//create raw socket

	if(sd < 0)
	{
		perror("socket() error");
    exit(EXIT_FAILURE);
	}

	int val = 1;
	if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0)
  {
		perror("setsockopt error : ");
		exit(EXIT_FAILURE);
	}
	//else printf("socket() - Using SOCK_RAW socket is OK.\n");

	char SRC_IP[100];
	sprintf(SRC_IP, "%s", "INADDR_ANY");

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(SRC_IP);

	din.sin_addr.s_addr = inet_addr(address);
	din.sin_port = 0;
	din.sin_family = AF_INET;
	inet_pton (AF_INET, address, &(din.sin_addr));

	unsigned int fromlen = sizeof(din);

	int seq = 1;
	int old_seq = 1;
  int ttl = 64;

	int payload = 3;
 	cout<<"PING "<<hostname<<" ("<<address<<"), "<<msgsz<<"("<<sizeof(struct ip) + sizeof(struct icmph) + sizeof(struct timeval) + msgsz<<") bytes of data\n";

 	signal(SIGINT, sig_handler);

 	error_no = 0;
	while(1)
	{
		if(count == MAX_TRIES)
		{
			break;
		}

		count++;

	  char recv[BUF_SIZE];
		bzero(recv, BUF_SIZE);
		struct sockaddr_in d_router;
		socklen_t len_router = sizeof(struct sockaddr_in);
		old_seq = seq;

		bzero(buffer, BUF_SIZE);

		struct ip *ip_hdr = (struct ip *) buffer;		//populate ip heaader
		ip_hdr->ip_hl = 5;			//IP header length
    ip_hdr->ip_v = 4;				//version
    ip_hdr->ip_tos = 0;			//type of service
    ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct icmph) + sizeof(struct timeval) + msgsz;			//total packet length
    ip_hdr->ip_id =0;				//identification
    ip_hdr->ip_off = 0;			//offset
    ip_hdr->ip_ttl = 64;		//time to live
    ip_hdr->ip_p = IPPROTO_ICMP;			//protocol used
    inet_pton (AF_INET, SRC_IP, &(ip_hdr->ip_src));				//source IP
    inet_pton (AF_INET, address, &(ip_hdr->ip_dst));			//destication IP
    ip_hdr->ip_sum = compute_checksum ((unsigned short *) buffer, 20);

    struct icmph *icmphd = (struct icmph *) (buffer+20);		//populate custom icmp header
    icmphd->type = ICMP_ECHO;			//type of packet
    icmphd->code = 0;				//used for error cases checking
    icmphd->checksum = 0;			//used for checking packet corruption
    icmphd->un.echo.id = 0;			//identification
    icmphd->un.echo.sequence = seq;		//sequence number

    struct timeval tv1, tv2, tv3;
		gettimeofday(&tv1, NULL);

		memcpy(buffer + sizeof(struct ip) + sizeof(struct icmph), &tv1, sizeof(struct timeval));	//timeval in data section

		memset(buffer + sizeof(struct ip) + sizeof(struct icmph) + sizeof(struct timeval),'a',msgsz);		//payload

    icmphd->checksum = compute_checksum ((unsigned short *) (buffer+20), sizeof(struct ip) + sizeof(struct icmph) + sizeof(struct timeval) + msgsz);

		//sprintf((buffer + 28), "%d", payload);

    //send packets
		int b1;
		//cout<<"val1 -> "<<val1<<"\n";
		if((b1=sendto(sd, buffer, sizeof(struct ip) + sizeof(struct icmph) + sizeof(struct timeval) + msgsz, 0, (struct sockaddr *) & din, (socklen_t)sizeof(din))) < 0)		//icmp ECHO REQUEST packet sending
		{
			perror("Sendto error : ");
    	exit(EXIT_FAILURE);
		}
		else
		{
			//cout<<"b1-> "<<b1<<"\n";
			packets_sent++;
		}

		//cout<<b1<<endl;

		//set timeout of 2 seconds
		fd_set read;
		FD_ZERO(&read);
		FD_SET(sd, &read);

    struct timeval s2;    //2 second timeout
    s2.tv_sec = 2;
		s2.tv_usec = 0;

    int scan_activity;
		scan_activity = select(101, &read, NULL, NULL, &s2);

		ssize_t bytes;
		bzero(buffer, BUF_SIZE);

		int is_recv = 0;
		//check for timeout
		if(FD_ISSET(sd, &read))
		{
			//receive reply packet (error packet or echo reply packet)
			if((bytes = recvfrom(sd, recv, sizeof(recv), 0, (struct sockaddr*)&d_router, &len_router)) < 0)
			{
				perror("recvfrom error : ");
			}
			else
			{
				is_recv = 1;
				gettimeofday(&tv2, NULL);
				struct timeval *t = (struct timeval*)(recv + 28);

				timersub(&tv2, t, &tv3);
				rtt[packets_recv++] = (tv3.tv_sec)*1000 + (tv3.tv_usec)/1000.0;
			}
		}

		struct ip *rec_ip = (struct ip*)(recv);
		int ttl_1 = rec_ip->ip_ttl;
		struct icmph *rec_icmp = (struct icmph*)(recv + 20);
		//cout<<rec_icmp->un.echo.sequence<<endl;

		int case3 = 0;
		if(is_recv == 1)			//some packet has been received
		{
			//check the checksum value of returning packet for corrupt data
			if(compute_checksum((short unsigned int *)(recv+sizeof(struct ip)), bytes - sizeof(struct ip)) == 0)	//check if returned checksum is 0 or not
			{
				//check validity of returned data
				if(rec_icmp->type == 0 && rec_icmp->un.echo.id == icmphd->un.echo.id && rec_icmp->un.echo.sequence == seq)		//ECHO_REPLY packet received
				{
					cout << bytes - sizeof(struct ip) << " bytes from ";
					char host[1024];
					char service[20];

					struct sockaddr_in sa;
					inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

					struct hostent *hp;
					struct in_addr ip;

					if (!inet_aton(inet_ntoa(d_router.sin_addr), &ip))
		    	{
				    errx(1, "can't parse IP address %s", argv[1]);
		    	}

					if((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)		//reverse DNS lookup
		    	{
						cout<<inet_ntoa(d_router.sin_addr);
		    	}
		    	else
					{
		    		cout<<hp->h_name<<"  ("<<inet_ntoa(d_router.sin_addr) <<") ";
					}

					cout<<" icmp_seq="<<seq<<"  ttl="<<ttl_1<<"  time="<<rtt[packets_recv-1]<<" ms"<<endl;
				}
				else if(rec_icmp->type == 3 && rec_icmp->code == 10) 		//destination host prohibited error case
				{
					error_no++;
					cout <<"From ";
					char host[1024];
					char service[20];

					struct sockaddr_in sa;
					inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

					struct hostent *hp;
					struct in_addr ip;

					if (!inet_aton(inet_ntoa(d_router.sin_addr), &ip))
		    	{
				    errx(1, "can't parse IP address %s", argv[1]);
		    	}

					if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)		//reverse DNS Lookup
		    	{
						cout<<inet_ntoa(d_router.sin_addr);
		    	}
		    	else
					{
			    		cout<<hp->h_name<<"  ("<<inet_ntoa(d_router.sin_addr) <<") ";
					}
					cout<<" icmp_seq="<<seq<<"  Destination Host Prohibited"<<endl;
				}
				else if(rec_icmp->type == 3 && rec_icmp->code == 1)					//destination host unrechable error case
				{
					error_no++;
					cout <<"From ";
					char host[1024];
					char service[20];

					struct sockaddr_in sa;
					inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

					struct hostent *hp;
					struct in_addr ip;

					if (!inet_aton(inet_ntoa(d_router.sin_addr), &ip))
		    	{
				    errx(1, "can't parse IP address %s", argv[1]);
		    	}

					if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)		//reverse DNS Lookup
		    	{
					cout<<inet_ntoa(d_router.sin_addr);
		    	}
		    	else
					{
		    		cout<<hp->h_name<<"  ("<<inet_ntoa(d_router.sin_addr) <<") ";
					}

					cout<<" icmp_seq="<<seq<<"  Destination Host Unreachable"<<endl;
				}
				else 			//damaged / corrupt packet case
				{
					case3 = 1 ;
				}
			}
			else 			//damaged / corrupt packet case
			{
				error_no++;
				cout <<"From ";
				char host[1024];
				char service[20];

				struct sockaddr_in sa;
				inet_pton(AF_INET, inet_ntoa(d_router.sin_addr), &sa.sin_addr);

				struct hostent *hp;
				struct in_addr ip;

				if (!inet_aton(inet_ntoa(d_router.sin_addr), &ip))
				{
					errx(1, "can't parse IP address %s", argv[1]);
				}

				if ((hp = gethostbyaddr((const void *)&ip, sizeof ip, AF_INET)) == NULL)		//reverse DNS Lookup
				{
					cout<<inet_ntoa(d_router.sin_addr);
				}
				else
				{
						cout<<hp->h_name<<"  ("<<inet_ntoa(d_router.sin_addr) <<") ";
				}
				cout<<" icmp_seq="<<seq<<"  Damaged packet received"<<endl;
			}

			sleep(1);		//wait for sometime for clear output
		}
		if(case3 != 1)	//if not a corrupt packet
		{
			seq++;		//increment sequence no
		}
	}
	sig_handler(SIGINT);
	return 0;
}
