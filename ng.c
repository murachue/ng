// ng: network graphicalizer
//  by Murachue, Mac support by masawaki
//  Inspired from Ghost In The Shell(world)/Innocence(network)
//  Referenced traceroute's source
//  20080821  idea
//  20080822- coding
//  20081012-20081013 First exhibition
//  20081014-20081015 QuickPort for FreeBSD7
// Copyright 2019 Murachue <murachue+github@gmail.com> and masawaki.
// License: GPLv2 (from traceroute: https://sourceforge.net/projects/traceroute/files/traceroute/traceroute-2.0.3/traceroute-2.0.3.tar.gz/download)

// TODO: Unmap window before wait threads suiciding.


#define _GNU_SOURCE	// use GNU extensions

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <sys/types.h>
#include <sys/socket.h>
//#include <net/if.h>	// ?
#include <netinet/in.h>	// ? (for IPPROTO_*)
#include <pcap.h>
#include <netinet/if_ether.h>	// ethernet
#define __FAVOR_BSD
#include <netinet/in_systm.h>	// for BSD, ip
#include <netinet/ip.h>		// ip
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#define IPARGL(i) (((i)>>24)&255),(((i)>>16)&255),(((i)>>8)&255),((i)&255)
#define IPARGB(i) ((i)&255),(((i)>>8)&255),(((i)>>16)&255),(((i)>>24)&255)
#ifdef __APPLE__
#define IPARG(i) IPARGB(i)
#else
// TODO: Some linux systems need IPARGL instead of IPARGB. What the hell?
//#define IPARG(i) IPARGL(i)
#define IPARG(i) IPARGB(i)
#endif
#define IPFMT "%d.%d.%d.%d"

#define FONT_NORMAL "-*-*-medium-r-*-*-10-*-*-*-*-*-*-*"
#define FONT_GLOBE  "-*-Kremlin-medium-r-*-*-10-*-*-*-*-*-*-*"

#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdarg.h>

#include <sys/stat.h>	// for BSD, stat

#ifdef BSD
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#define ICMP_DEST_UNREACH ICMP_UNREACH
#define ICMP_EXC_TTL ICMP_TIMXCEED_INTRANS
char *strndup(const char *s, size_t n)
{
	char *p;

	if((p = malloc(n + 1)) == NULL)
	{
		return NULL;
	}
	strncpy(p, s, n);
	p[n] = '\0';

	return p;
}
#else	// LINUX
#define icmp_type type
#define icmp_code code
#endif
#ifdef __APPLE__
#define icmphdr icmp
#define IP_PMTUDISC_DONT 0
#endif

#define TRUE 1
#define FALSE 0

/*
 * Nicer: Extend(traceroute) when point
 *      : Use Pong-TTL, it may be 255 or 128 or... but subtract to detect hops?, TTL is 8bit.
 *      :  http://www.tef-room.net/main/icmp.html
 */

// traceroute.h
/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL

    See COPYING for the status of this software.
*/
union common_sockaddr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};
typedef union common_sockaddr sockaddr_any;

struct probe_struct {
	int done;
	int final;
	sockaddr_any res;
	double send_time;
	double recv_time;
	int sk;
	int seq;
	int rttl;
	char err_str[16];	/*  assume enough   */
};
typedef struct probe_struct probe;

// time.c
/*
    Copyright (c) 2000, 2003	    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL

    See COPYING for the status of this software.
*/
double get_time_double(struct timeval *tv)
{
	return ((double) tv->tv_usec) / 1000000. + (unsigned long) tv->tv_sec;
}
double get_time (void) {
	struct timeval tv;
	//double d;

	gettimeofday (&tv, NULL);

	//d = ((double) tv.tv_usec) / 1000000. + (unsigned long) tv.tv_sec;

	//return d;
	return get_time_double(&tv);
}

// traceroute.c: prototype
/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL

    See COPYING for the status of this software.
*/
void tune_socket (int sk) ;
static int getaddr (const char *name, sockaddr_any *addr) ;
double get_timestamp (struct msghdr *msg) ;
void parse_icmp_res (probe *pb, int type, int code) ;
//static const char *addr2str (const sockaddr_any *addr) ;

// icmp.c
/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL

    See COPYING for the status of this software.
*/
/*
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>
*/
#include <sys/poll.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

static sockaddr_any dest_addr = {{ 0, }, };
static u_int16_t seq = 1;
static u_int16_t ident = 0;

static char *data = NULL;
static size_t data_len = 0;

static int icmp_sk = -1;
static int last_ttl = 0;

static u_int16_t in_cksum (const void *ptr, size_t len) {
	const u_int16_t *p = (const u_int16_t *) ptr;
	unsigned int sum = 0;
	u_int16_t res;

	while (len > 1) {
	    sum += *p++;
	    len -= 2;
	}

	if (len)
	    sum += htons (*((unsigned char *) p) << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	res = ~sum;
	if (!res)  res = ~0;

	return res;
}

static struct pollfd pfd;

static int icmp_settarget(const char *host, const sockaddr_any *dest, unsigned int port_seq, size_t packet_len)
{
	int i;
	//int af = dest->sa.sa_family;

	if(icmp_sk == -1)
		return 1;

	dest_addr = *dest;
	memset(dest_addr.sin.sin_zero, 0, 8);
	dest_addr.sin.sin_port = 0;
	if(host && getaddr(host, &dest_addr))
		return 1;

	if (port_seq)  seq = port_seq;

	if(data)
		free(data);

	data_len = sizeof (struct icmphdr) + packet_len;
	if(!(data = malloc (data_len)))
		return 1;

        for (i = sizeof (struct icmphdr); i < data_len; i++)
                data[i] = 0x40 + (i & 0x3f);

	return 0;
}

static int icmp_init (int af) {
	if((icmp_sk = socket (af, SOCK_RAW, IPPROTO_ICMP)) < 0)
		return 1;

	tune_socket (icmp_sk);

	pfd.fd = icmp_sk;
	pfd.events = POLLIN;

	ident = getpid () & 0xffff;
 
	return 0;
}

static int icmp_send_probe (probe *pb, int ttl) {
	int af = dest_addr.sa.sa_family;

	if(icmp_sk == -1)
		return 1;

	if (ttl != last_ttl) {
	    if (af == AF_INET) {
		if (setsockopt (icmp_sk, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
		{
			puts("send:TTLcantset");
			return 1;
		}
	    }

	    last_ttl = ttl;
	}

	if (af == AF_INET) {
	    struct icmp *icmp = (struct icmp *) data;

	    icmp->icmp_type = ICMP_ECHO;
	    icmp->icmp_code = 0;
	    icmp->icmp_cksum = 0;
	    icmp->icmp_id = htons (ident);
	    icmp->icmp_seq = htons (seq);

	    icmp->icmp_cksum = in_cksum (data, data_len);
	}

	pb->send_time = get_time ();

	if (sendto (icmp_sk, data, data_len, 0, &dest_addr.sa, sizeof (dest_addr)) < 0)
	{
		puts("send:Cantsend");
		return 1;
	}

	pb->seq = seq;

	seq++;

	return 0;
}


static int icmp_recv_probe (int sk, int revents, probe *probes, unsigned int num_probes) {
	int af = dest_addr.sa.sa_family;
	struct msghdr msg;
	sockaddr_any from;
	struct iovec iov;
	int n, type, code;
	u_int16_t recv_id, recv_seq;
	probe *pb;
	char buf[1024];		/*  enough, enough...  */
	char control[1024];
	int rttl;

	if(icmp_sk == -1)
		return 1;

	if (!(revents | POLLIN))
		return 1;

	memset (&msg, 0, sizeof (msg));
	msg.msg_name = &from;
	msg.msg_namelen = sizeof (from);
	msg.msg_control = control;
	msg.msg_controllen = sizeof (control);
	iov.iov_base = buf;
	iov.iov_len = sizeof (buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	n = recvmsg (sk, &msg, 0);
	if (n < sizeof (struct icmphdr))	/*  error or too short   */
	{
		puts("short");
		return 1;
	}


	if (af == AF_INET) {
	    struct ip *ip = (struct ip *) buf;
	    int hlen = ip->ip_hl << 2;
	    struct icmp *icmp;

#ifdef __APPLE__
		// XXX: maybe Mac's recvmsg's return value is size of only payload...
		n -= /*hlen +*/ sizeof (struct icmphdr) - sizeof (((struct icmphdr*)0)->icmp_dun);
#else
	    n -= hlen + sizeof (struct icmphdr);
#endif
	    if (n < 0){	puts("ip_short");  return 1;}

	    rttl = ip->ip_ttl;
	    icmp = (struct icmp *) (buf + hlen);
	    type = icmp->icmp_type;
	    code = icmp->icmp_code;

	    if (type == ICMP_ECHOREPLY) {
		    recv_id = ntohs (icmp->icmp_id);
		    recv_seq = ntohs (icmp->icmp_seq);
	    }
	    else if (type == ICMP_TIME_EXCEEDED ||
		     type == ICMP_DEST_UNREACH
	    ) {
			if (n < sizeof (struct ip) + sizeof (struct icmphdr))
			{
				printf("icmp_short(%d < %zd+%zd)\n", n, sizeof (struct ip), sizeof (struct icmphdr));
				/*
				{
					int i;
					for(i = 0; i < n + 8; i++)
						printf("%02X ", ((unsigned char *)&icmp->icmp_ip)[i]);
				}
				puts("");
				*/
				return 1;
			}

#ifdef BSD
			ip = /*(struct ip *)*/ &icmp->icmp_ip;	// MTU?
#else
			ip = (struct ip *) (((char *)icmp) + sizeof(struct icmphdr));
#endif
			hlen = ip->ip_hl << 2;

			if (n < hlen + sizeof (struct icmphdr))
			{
				puts("any_short");
				return 1;
			}
			if (ip->ip_p != IPPROTO_ICMP)
			{
				printf("RETRY: not_icmp: %d\n", ip->ip_p);
/*
				{
					int i;
					for(i = 0; i < n + (((struct ip*)buf)->ip_hl<<2)+sizeof(struct icmphdr); i++)
					{
						printf("%02X ", (int)(unsigned int)(unsigned char)buf[i]);
						if(i % 16 == 15)
							puts("");
					}
					puts("");
				}
*/
				return 2;
			}

			icmp = (struct icmp *) (((char *) ip) + hlen);
			recv_id = ntohs (icmp->icmp_id);
			recv_seq = ntohs (icmp->icmp_seq);

	    } else
		{
		printf("not_icmp_type: %d\n", type);
		return 2;
		}
	}


	if (recv_id != ident)
	{
		printf("RETRY: ne_ident: %d!=%d\n", recv_id, ident);
		return 2;
	}

	for (n = 0; n < num_probes && probes[n].seq != recv_seq; n++) ;
	if (n >= num_probes)
	{
		printf("no_probe: %d not in ", recv_seq);
		for(n = 0; n < num_probes; n++)
			printf("%d ", probes[n].seq);
		puts("");
		return 2;	// TODO: I just ignore, but should check remain in socket buffer..
	}
	pb = &probes[n];

	pb->rttl = rttl;

	memcpy (&pb->res, &from, sizeof (pb->res));

	if (af == AF_INET && type == ICMP_ECHOREPLY)
	{
	    pb->final = 1;
	} else
	    parse_icmp_res (pb, type, code);

	pb->recv_time = get_timestamp (&msg);


	//pb->seq = -1;

	pb->done = 1;

	return 0;
}

// traceroute.c
/*
    Copyright (c)  2006		    Dmitry K. Butskoy
				    <buc@citadel.stu.neva.ru>
    License:  GPL

    See COPYING for the status of this software.
*/
/*
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <errno.h>
#include <locale.h>
#include <linux/types.h>
#include <linux/errqueue.h>
*/
#include <fcntl.h>
#include <netdb.h>
#  define AI_IDN	0x0040	/* IDN encode input (assuming it is encoded
				   in the current locale's character set)
				   before looking it up. */
#  define NI_IDN	32	/* Convert name from IDN format.  */
#define DEF_AF		AF_INET


void tune_socket (int sk) {
	int i = 0;

/*
	if (device) {
	    if (setsockopt (sk, SOL_SOCKET, SO_BINDTODEVICE,
					device, strlen (device) + 1) < 0
	    )  error ("setsockopt SO_BINDTODEVICE");
	}

	if (src_addr.sa.sa_family) {
	    if (bind (sk, &src_addr.sa, sizeof (src_addr)) < 0)
		    error ("bind");
	}
*/

#ifndef BSD	// TODO: Is this ok?
	i = IP_PMTUDISC_DONT;
	if (setsockopt (sk, IPPROTO_IP, IP_MTU_DISCOVER, &i, sizeof(i)) < 0)
		;
#endif

	i = 1;
	setsockopt (sk, SOL_SOCKET, SO_TIMESTAMP, &i, sizeof (i));

	fcntl (sk, F_SETFL, O_NONBLOCK);

	return;
}

static int getaddr (const char *name, sockaddr_any *addr) {
	int ret;
	struct addrinfo hints, *ai, *res = NULL;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_IDN;

	ret = getaddrinfo (name, NULL, &hints, &res);
	if (ret) {
		fprintf (stderr, "%s: %s\n", name, gai_strerror (ret));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
	    if (ai->ai_family == AF_INET)  break;
	    /*  when af not specified, choose DEF_AF if present   */
	    if (!AF_INET && ai->ai_family == DEF_AF)
		    break;
	}
	if (!ai)  ai = res;	/*  anything...  */

	if (ai->ai_addrlen > sizeof (*addr))
		return -1;	/*  paranoia   */
	memcpy (addr, ai->ai_addr, ai->ai_addrlen);

	freeaddrinfo (res);

	return 0;
}

double get_timestamp (struct msghdr *msg) {
	struct cmsghdr *cm;
	double timestamp = 0;

	for (cm = CMSG_FIRSTHDR (msg); cm; cm = CMSG_NXTHDR (msg, cm)) {

	    if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SO_TIMESTAMP) {
		struct timeval *tv = (struct timeval *)  CMSG_DATA (cm);

		timestamp = tv->tv_sec + tv->tv_usec / 1000000.;
	    }
	}

	if (!timestamp)
		timestamp = get_time ();

	return timestamp;
}

void parse_icmp_res (probe *pb, int type, int code) {
	char *str = "";
	char buf[16];

	//if (af == AF_INET) {

	    if (type == ICMP_TIME_EXCEEDED) {
		if (code == ICMP_EXC_TTL)
			return;
	    }
	    else if (type == ICMP_DEST_UNREACH) {

		switch (code) {
		    case ICMP_UNREACH_NET:
		    case ICMP_UNREACH_NET_UNKNOWN:
		    case ICMP_UNREACH_ISOLATED:
		    case ICMP_UNREACH_TOSNET:
			    str = "!N";
			    break;

		    case ICMP_UNREACH_HOST:
		    case ICMP_UNREACH_HOST_UNKNOWN:
		    case ICMP_UNREACH_TOSHOST:
			    str = "!H";
			    break;

		    case ICMP_UNREACH_NET_PROHIB:
		    case ICMP_UNREACH_HOST_PROHIB:
		    case ICMP_UNREACH_FILTER_PROHIB:
			    str = "!X";
			    break;

		    case ICMP_UNREACH_PORT:
			    /*  dest host is reached   */
			    str = NULL;
			    break;

		    case ICMP_UNREACH_PROTOCOL:
			    str = "!P";
			    break;

		    case ICMP_UNREACH_NEEDFRAG:
			    str = "!F";
			    break;

		    case ICMP_UNREACH_SRCFAIL:
			    str = "!S";
			    break;

		    case ICMP_UNREACH_HOST_PRECEDENCE:
			    str = "!V";
			    break;

		    case ICMP_UNREACH_PRECEDENCE_CUTOFF:
			    str = "!C";
			    break;

		    default:
			    snprintf (buf, sizeof (buf), "!<%u>", code);
			    str = buf;
			    break;
		}
	    }

	//}

	if (str && !*str) {
	    snprintf (buf, sizeof (buf), "!<%u-%u>", type, code);
	    str = buf;
	}

	if (str) {
	    strncpy (pb->err_str, str, sizeof (pb->err_str));
	    pb->err_str[sizeof (pb->err_str) - 1] = '\0';
	}

	pb->final = 1;

	return;
}

int dopoll(double timeout, probe *p)
{
	int n;
repoll:
	n = poll (&pfd, 1, timeout * 1000);	// TODO: this replacable select()??
	if (n < 0) {
		if (errno == EINTR)  return 1;
		return 1;
	}

	if (pfd.revents) {
		switch(icmp_recv_probe (pfd.fd, pfd.revents, p, 1))
		{
			case 0:	// Successful
				break;
			case 1:	// Error
				puts("Error on icmp_recv_probe");
				return 0;
				break;
			case 2:	// Not ICMP(will UDP)
				goto repoll;
				break;
		}
		n--;

		return 1;
	}
	return 0;
}

/*
static char addr2str_buf[INET6_ADDRSTRLEN];

static const char *addr2str (const sockaddr_any *addr) {

        getnameinfo (&addr->sa, sizeof (*addr),
                addr2str_buf, sizeof (addr2str_buf), 0, 0, NI_NUMERICHOST);

        return addr2str_buf;
}
*/

/////////////////////////
// ng.c
/////////////////////////

pthread_mutex_t pmNodes = PTHREAD_MUTEX_INITIALIZER;
struct tagTraffic
{
	size_t pktsize;
	double time;
	struct tagNode *target;
	int isuplink;

	int proto;

	struct tagTraffic *next;
};

struct tagNode
{
	u_int32_t ip;
	char *name;

	int x, y;
	int ping;
	int leafs;	// leaves but I'm poor to english, so it's easy to understand for me.
	int childs;	// children but (omit)

	int resolved;
	int tracerouted;
	int pingfail;
	int marked;

	double tradd;	// Time of Recent ADD

	char *packet[3];
	char *packetptr[3];

	struct{
		int x, y;
		int px, py;
		double deg;
	}posinfo;

	u_int64_t upbyte, downbyte;

	struct tagTraffic *traffic;

	int cityindex;

	struct tagNode *parent;
	struct tagNode *child;
	struct tagNode *next;
} nroot, *cnode = NULL;

struct tagMatrix3
{
	double x, y, z;
};
typedef struct tagMatrix3 M3;

struct tagBound
{
	int left, top, right, bottom;
};

typedef int bool;
typedef unsigned long ulong;

struct
{
	int runode;
	bool showinfo;

	int maxhop;

	int posmode;
	int movemode;

	bool autodns;
	bool autotrace;
	bool autonode;
	bool autogo;
	bool autorotate;

	int minping;
	int maxping;

	bool logstdout;

	int traceInterval;
	int traceHopInterval;

	int clock;

	int nodeRadius;
	int rootRadius;
	bool viewPacket;

	char *colorName;
	ulong colorPx;

	int bundle;

	bool viewTraffic;
	bool packetLog;

	bool threed;

	struct{
		char *tcp;
		ulong tcpPx;
		char *udp;
		ulong udpPx;
		char *icmp;
		ulong icmpPx;
	}protocolor;

	double rotate;

	double xshrink, yshrink;

	M3 lookat;
	M3 lookup;
	M3 eye;
	double fov;

	bool showpktsize;
	bool showbytes;

	bool clipping;

	struct
	{
		bool enabled;
		double interval;
		double radius;
		double size;
	}threedgrid;

	double pktinterval;

	double threedzn;
	double threedzf;

	bool globe;
	double globerad;
	bool globeip;
	double globerotdx;
	double globelineheight;
	unsigned int globelinediv;
	bool globehilight;
	char *globehlcolor;
	ulong globehlcolorPx;
	char *globegridcolor;
	ulong globegridcolorPx;
	char *globeinterncolor;
	ulong globeinterncolorPx;
	bool globeshowonlymetro;

	unsigned int restfps;	// restriction fps

	int pktdispatchcnt;
} gconf =  // Global CONFigulation
{
	.runode = 100,
	.showinfo = TRUE,

	.maxhop = 0,

	.posmode = 0,
	.movemode = -1,	// -1: level-follow-coefficient, 0: atonce, >1: specified-follow-coefficient

	.autodns = FALSE,
	.autotrace = FALSE,
	.autonode = FALSE,
	.autogo = FALSE,
	.autorotate = FALSE,

	.minping = 20,
	.maxping = 200,

	.logstdout = FALSE,

	.traceInterval = 1,
	.traceHopInterval = 100000,

	.clock = 1,

	.nodeRadius = 10,
	.rootRadius = 15,
	.viewPacket = 0,

	.colorName = "rgb:FF/90/30",

	.bundle = 0,

	.viewTraffic = FALSE,
	.packetLog = FALSE,

	.threed = FALSE,

	.protocolor = {
		.tcp = "yellow",
		.udp = "magenta",
		.icmp = "white",
	},

	.rotate = 0.0,

	.lookat = {0.0, 0.0, 0.0},
	.lookup = {0.0, 1.0, 0.0},
	.eye = {0.0, 50.0, 150.0},
	.fov = 90.0,

	.showpktsize = TRUE,
	.showbytes = FALSE,

	.clipping = FALSE,

	.threedgrid = {
		.enabled = FALSE,
		.interval = 20,
		.radius = 5,
		.size = 3,
	},

	.pktinterval = 0.5,

	.threedzn = 5.0,
	.threedzf = 2500.0,

	.globe = FALSE,
	.globeip = FALSE,
	.globerotdx = 0.0003,
	.globelineheight = 25.0,
	.globelinediv = 32,
	.globerad = 100.0,
	.globehilight = TRUE,
	.globehlcolor = "white",
	.globegridcolor = "rgb:80/40/10",
	.globeinterncolor = "rgb:c0/60/20",
	.globeshowonlymetro = FALSE,

	.restfps = 0,

	.pktdispatchcnt = 1,
};

struct
{
	int cdragging;
	int cmdmode;
	char cmdstr[256];
	int quitting;

	int savecnt;
	int loadcnt;
	int nukecnt;

	int dragpx, dragpy;
	double dragpd;

	double ctime;	// CurrentTIME (on buildNetwork)

	size_t fsize;	// filesize
	unsigned int phase;	// loading phase(for AA)

	double transM44[4][4];
	double saveTransM44[4][4];
	double prevTransM44[4][4];

	double lasttime;
	int fps;
	int points;
	int curframespersec;
	int curpointspersec;
	int curpointsperframe;

	int tdragging;
	int tdragged;

	struct timeval packettv;
	bool isoffline;

	struct{
		M3 *points;
		int cpoints;
		int (*lines)[2];
		int clines;
	}model;
} gstat = // Global STATus
{
	.cdragging = FALSE,
	.cmdmode = FALSE,
	//.cmdstr,
	.quitting = FALSE,

	.savecnt = 0,
	.loadcnt = 0,
	.nukecnt = 0,

	.isoffline = FALSE,

	.model = {
		.points = NULL,
		.lines = NULL,
		.cpoints = 0,
		.clines = 0,
	},
};
struct{
	struct{
		char *country;
		char *cityname;
		double x, y;
		unsigned long popul;
		int ismetro;
	}*cities;
	struct{
		int cpoints;
		struct{
			double x, y;
		}*pts;
	}*coasts, *interns;
	struct{
		u_int32_t ip;
		u_int32_t mask;
		int cid;	// cities id(array offset)
	}*ips;
	int ccities, ccoasts, cinterns, cips;

	double rot;
}gGlobe = {
	.cities = NULL,
	.coasts = NULL,
	.interns = NULL,
	.ips = NULL,

	.ccities = 0,
	.ccoasts = -1,
	.cinterns = -1,
	.cips = 0,

	.rot = 0.0,
};

const char loadchar[4] = {'/', '-', '\\', '|'};

struct tagLog
{
	int lines;
	char **log;
	pthread_mutex_t pmLog;
} logs[] = {
	{ 10, NULL, PTHREAD_MUTEX_INITIALIZER },
	{ 15, NULL, PTHREAD_MUTEX_INITIALIZER },
};

pthread_mutex_t pmTraces = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pmTraceRunner = PTHREAD_MUTEX_INITIALIZER;
pthread_t pthTraceRunner = 0;
struct tagNode **traces = NULL;
int ctraces = 0;
pthread_mutex_t pmResolves = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pmResolveRunner = PTHREAD_MUTEX_INITIALIZER;
pthread_t pthResolveRunner = 0;
struct tagNode **resolves = NULL;
int cresolves = 0;

struct
{
	Display *disp;
	Window wnd;
	GC gc, gcStripe;
	Font font, fontKrem;
	XFontStruct *fontst, *fontKremst;
	Pixmap pm;

	int ww, wh;
} X;

/*
[user@host ~]$ ping somehost
PING somehost (11.11.11.11) 56(84) bytes of data.
64 bytes from somehost (11.11.11.11): icmp_seq=1 ttl=253 time=3.33 ms
64 bytes from somehost (11.11.11.11): icmp_seq=2 ttl=253 time=3.33 ms

[user@host ~]$ sudo traceroute -I somehost
traceroute to somehost (11.11.11.11), 30 hops max, 40 byte packets
1  33.33.33.33 (33.33.33.33)  1.111 ms  1.111 ms  1.111 ms
2  somerouter (22.22.22.22)  2.222 ms  2.222 ms  2.222 ms
3  somehost (11.11.11.11)  3.333 ms  3.333 ms  3.333 ms

[user@host ~]$ 
*/

int suggestHop(int rttl)
{
	int hop;

	     if(rttl > 255 - 30)
		hop = 255 - rttl;
	else if(rttl > 155 - 30)	// i can't believe this TTL...
		hop = 155 - rttl;
	else if(rttl > 128 - 30)
		hop = 128 - rttl;
	else if(rttl > 100 - 30)
		hop = 100 - rttl;
	else if(rttl > 64 - 30)
		hop = 64 - rttl;
	else if(rttl > 60 - 30)
		hop = 60 - rttl;
	else if(rttl > 0)
		hop = 30 - rttl;

	return hop;
}

// realloc have many "implementation depended behavior", so I define it here.
void *remalloc(void *ptr, size_t size)
{
	if(!ptr && !size)
		return NULL;

	if(!ptr && size)
		return malloc(size);

	if(ptr && !size)
	{
		free(ptr);
		return NULL;
	}

	return realloc(ptr, size);	// defined exactly, "return ptr to reallocated buffer, or when failed org buffer isn't touched"
}

static char addr2name_buf[1025];
static const char *addr2name(u_int32_t ip)
{
	struct sockaddr_in in;

	addr2name_buf[0] = '\0';

	in.sin_family = AF_INET;
	in.sin_port = 0;
	in.sin_addr.s_addr = ip;

	if(getnameinfo ((struct sockaddr*)&in, sizeof (in), addr2name_buf, sizeof (addr2name_buf), 0, 0, NI_NAMEREQD | NI_IDN))
		return NULL;

	return addr2name_buf;
}

unsigned long GetColor(Display *dis, char *cname)
{
	Colormap cmap;
	XColor near, true;

	cmap = DefaultColormap(dis, 0);
	if(!XAllocNamedColor(dis, cmap, cname, &near, &true))
		return -1;

	return near.pixel;
}

void logstr(int logid, const char *str)
{
	struct tagLog *log = &logs[logid];
	int i;

	if(gconf.logstdout && logid == 0)
		puts(str);

	pthread_mutex_lock(&log->pmLog);

	if(!log->log && log->lines)
		log->log = calloc(log->lines, sizeof(char*));

	if(log->log)
	{
		if(log->log[log->lines - 1])
			free(log->log[log->lines - 1]);
		for(i = log->lines - 2; i >= 0; i--)
		{
			log->log[i + 1] = log->log[i];
		}

		if(!str)
			log->log[0] = NULL;
		else
			log->log[0] = strdup(str);
	}

	pthread_mutex_unlock(&log->pmLog);

	return;
}

void logstrf(int logid, const char *fmt, ...)
{
	va_list va;
	char ts[1024];

	va_start(va, fmt);
	vsnprintf(ts, sizeof(ts), fmt, va);
	va_end(va);

	logstr(logid, ts);

	return;
}

void *resolveRunner(void *param)
{
	for(; cresolves;)
	{
		int i;
		struct tagNode *resolvee;

		pthread_mutex_lock(&pmResolves);
		resolvee = resolves[0];
		cresolves--;
		for(i = 0; i < cresolves; i++)
			resolves[i] = resolves[i + 1];
		pthread_mutex_unlock(&pmResolves);

		if(!resolvee->resolved)
		{
			const char *name = addr2name(resolvee->ip);
			if(name)
			{
				resolvee->name = strdup(name);
				logstrf(0, "Resolved "IPFMT" as %s, remain %d.", IPARG(resolvee->ip), resolvee->name, cresolves);
			}else
			{
				resolvee->name = NULL;
				logstrf(0, "Resolve "IPFMT" failed, remain %d.", IPARG(resolvee->ip), cresolves);
			}
			resolvee->resolved = TRUE;
		}

		usleep(100000);
	}

	logstr(0, "All name resolving completed.");

	pthread_mutex_lock(&pmResolveRunner);
	pthResolveRunner = 0;
	pthread_mutex_unlock(&pmResolveRunner);

	pthread_exit(NULL);
	return 0;
}

void resolveAdd(struct tagNode *node)
{
	int i;

	pthread_mutex_lock(&pmResolves);
	for(i = 0; i < cresolves; i++)
		if(resolves[cresolves] == node)
		{
			pthread_mutex_unlock(&pmResolves);
			return;
		}

	resolves = remalloc(resolves, sizeof(*resolves) * (cresolves + 1));
	resolves[cresolves] = node;
	cresolves++;
	pthread_mutex_unlock(&pmResolves);

	pthread_mutex_lock(&pmResolveRunner);
	if(!pthResolveRunner)
	{
		if(pthread_create(&pthResolveRunner, NULL, resolveRunner, NULL))
		{
			puts("Cannot create resolve thread!!");
			pthread_mutex_unlock(&pmResolveRunner);
			return;
		}
		pthread_detach(pthResolveRunner);
	}
	pthread_mutex_unlock(&pmResolveRunner);

	return;
}

struct tagNode *searchNodeByIPFrom(in_addr_t ip, struct tagNode *node)
{
	for(; node; node = node->next)
	{
		if(node->ip == ip)
			return node;

		if(node->child)
		{
			struct tagNode *ret;
			if((ret = searchNodeByIPFrom(ip, node->child)) != NULL)
				return ret;
		}
	}

	return NULL;
}

struct tagNode *searchNodeByIP(in_addr_t ip)
{
	return searchNodeByIPFrom(ip, &nroot);
}

struct tagNode *searchNodeByNameFrom(const char *name, struct tagNode *node)
{
	for(; node; node = node->next)
	{
		if(node->name && !strcmp(node->name, name))
			return node;

		if(node->child)
		{
			struct tagNode *ret;
			if((ret = searchNodeByNameFrom(name, node->child)) != NULL)
				return ret;
		}
	}

	return NULL;
}

struct tagNode *searchNodeByName(const char *name)
{
	return searchNodeByNameFrom(name, &nroot);
}

struct tagNode *newNode(struct tagNode *parent, int flags)
{
	struct tagNode *node;
	int i;

	if((node = malloc(sizeof(*node))) == NULL)
		return NULL;

	if(!parent)
		parent = &nroot;

	// set IP
	node->ip = 0;
	node->name = NULL;	//"hoge";

	// set info
	node->x = parent->x;
	node->y = parent->y;
	node->ping = 100;
	node->resolved = 0;
	node->tracerouted = 0;
	node->pingfail = 0;
	node->tradd = 0;
	node->marked = 0;

	node->upbyte = 0;
	node->downbyte = 0;

	for(i = 0; i < 3; i++)
		node->packet[i] = NULL;

	node->leafs = 0;
	node->childs = 0;
	
	node->traffic = NULL;

	node->cityindex = -1;

	// set parent&child info
	node->parent = parent;
	node->child = NULL;
	node->next = NULL;

	return node;
}

struct tagNode *beChildNodeOf(u_int32_t ip, struct tagNode *parent, int autodns)
{
	struct tagNode *node;

	if((node = newNode(parent, 0)) == NULL)
		return NULL;

	// set IP
	node->ip = ip;
	if(autodns)
		resolveAdd(node);

	// set info
	node->tradd = 0.0; //get_time();

	// Do append!
	node->next = parent->child;
	parent->child = node;

	//printf("beChild: %d.%d.%d.%d append to %d.%d.%d.%d(%d+): ", IPARG(node->ip), IPARG(parent->ip), parent->childs);

	parent->childs++;

	parent->leafs++;
	if(parent->leafs > 1)
		// child_counter++
		while((parent = parent->parent) != NULL)
		{
			//printf("%d.%d.%d.%d(%d+) ", IPARG(parent->ip), parent->leafs);
			parent->leafs++;
			//break;
		}
	//puts("");

	return node;
}

void traceAdd(struct tagNode *node);
struct tagNode *getOrAppendNode(u_int32_t ip, int autotrace)
{
	struct tagNode *node;

	if(!(node = searchNodeByIP(ip)))
	{
		node = beChildNodeOf(ip, &nroot, gconf.autodns);
		if(autotrace)
			traceAdd(node);
	}

	return node;	
}

int appendChildTo(struct tagNode *parent, struct tagNode *child)
{
	child->parent = parent;
	child->next = parent->child;
	parent->child = child;

	//printf("append: %d.%d.%d.%d append to %d.%d.%d.%d(%d+): ", IPARG(child->ip), IPARG(parent->ip), parent->childs);

	parent->childs++;

	{
		int leafs;

		leafs = child->leafs;
		if(leafs == 0)	// when child
			leafs = 1;

		parent->leafs += leafs;
		if(parent->leafs > 1)
		{
			// child_counter++
			while((parent = parent->parent) != NULL)
			{
				//printf("%d.%d.%d.%d(%d+) ", IPARG(parent->ip), parent->leafs);
				parent->leafs += leafs;
				//break;
			}
			//puts("");
		}
	}

	return 0;
}

int cutNode(struct tagNode *node)
{
	struct tagNode **pn;

	for(pn = &node->parent->child; *pn; pn = &(*pn)->next)
	{
		if(*pn == node)
		{
			int c;

			*pn = (*pn)->next;

			//printf("cutNode: %d.%d.%d.%d(%d) ", IPARG(node->ip), node->leafs);
			node->parent->childs--;

			c = node->leafs;
			if(c == 0)	// when child
				c = 1;

			node->parent->leafs -= c;

			if(node->parent->leafs > 0)
			{
				node = node->parent;
				while((node = node->parent) != NULL)	// node reuse
				{
					//printf("%d.%d.%d.%d(%d-) ", IPARG(node->ip), node->leafs);
					node->leafs -= c;
					//break;
				}
				//puts("");
			}
			return 0;
		}
	}

	return 1;
}

// http://www2.starcat.ne.jp/~fussy/algo/algo1-2.htm
enum Edge {
	LEFT = 1,
	RIGHT = 2,
	TOP = 4,
	BOTTOM = 8,
};

typedef struct Coord
{
	double x;
	double y;
} Coord;

Coord Min, Max;

int calc_seq_code( const Coord *c )
{
	int code = 0;
	if( c->x < Min.x ) code |= LEFT;
	if( c->x > Max.x ) code |= RIGHT;
	if( c->y < Min.y ) code |= TOP;
	if( c->y > Max.y ) code |= BOTTOM;

	return( code );
}

int calc_intsec_x( const Coord *c0, const Coord *c1, double clip_x, Coord* c )
{
	double cy = ( c1->y - c0->y ) * ( clip_x - c0->x ) / ( c1->x - c0->x ) + c0->y;

	if ( ( cy < Min.y ) || ( cy > Max.y ) ) return( 0 );

	c->x = clip_x;
	c->y = cy;

	return( 1 );
}

int calc_intsec_y( const Coord *c0, const Coord *c1, double clip_y, Coord* c )
{
	double cx = ( c1->x - c0->x ) * ( clip_y - c0->y ) / ( c1->y - c0->y ) + c0->x;

	if ( ( cx < Min.x ) || ( cx > Max.x ) ) return( 0 );

	c->x = cx;
	c->y = clip_y;

	return( 1 );
}

int calc_clipped_point( int code, const Coord *c0, const Coord *c1, Coord* c )
{
	if ( ( code & LEFT ) != 0 )
		if ( calc_intsec_x( c0, c1, Min.x, c ) )
			return( 1 );

	if ( ( code & RIGHT ) != 0 )
		if ( calc_intsec_x( c0, c1, Max.x, c ) )
			return( 1 );

	if ( ( code & TOP ) != 0)
		if ( calc_intsec_y( c0, c1, Min.y, c ) )
			return( 1 );

	if ( ( code & BOTTOM ) != 0 )
		if ( calc_intsec_y( c0, c1, Max.y, c ) )
			return( 1 );

	return( 0 );	// invisible
}

// 0: No clipping needed 1: Clipped -1: Invisible
int clipping( double *c0x, double *c0y, double *c1x, double *c1y, double minx, double miny, double maxx, double maxy )
{
	int code0, code1;
	Coord c0, c1;

	Min.x = minx;
	Min.y = miny;
	Max.x = maxx;
	Max.y = maxy;

	c0.x = *c0x;
	c0.y = *c0y;
	c1.x = *c1x;
	c1.y = *c1y;

	code0 = calc_seq_code( &c0 );
	code1 = calc_seq_code( &c1 );

	if ( ( code0 == 0 ) && ( code1 == 0 ) ) return( 0 );
	if ( ( code0 & code1 ) != 0 ) return( -1 );
	if( code0 != 0 && ! calc_clipped_point( code0, &c0, &c1, &c0 ) ) return( -1 );
	if( code1 != 0 && ! calc_clipped_point( code1, &c0, &c1, &c1 ) ) return( -1 );

	*c0x = c0.x;
	*c0y = c0.y;
	*c1x = c1.x;
	*c1y = c1.y;

	return( 1 );
}


#define SQR(n) ((n) * (n))
double distance(int x1, int y1, int x2, int y2)
{
	return sqrt(SQR(x2 - x1) + SQR(y2 - y1));
}

// http://www.sra.co.jp/people/miyata/algorithm/gjmatinv.txt
// http://imokoji.hamazo.tv/e1356674.html
//double matinv(int n, matrix a)
void invM44(double a[4][4])
{
	int i, j, k;
	double t, u;//, det;

	//det = 1;
	for (k = 0; k < 4; k++) {
		t = a[k][k];//  det *= t;
		for (i = 0; i < 4; i++) a[k][i] /= t;
		a[k][k] = 1 / t;
		for (j = 0; j < 4; j++)
			if (j != k) {
				u = a[j][k];
				for (i = 0; i < 4; i++)
					if (i != k) a[j][i] -= a[k][i] * u;
					else        a[j][i] = -u / t;
			}
	}
	return/* det*/;
}

double normM3(M3 *a)
{
	return sqrt(a->x*a->x + a->y*a->y + a->z*a->z);
}
M3 *normalM3(M3 *a)
{
	double npoly = normM3(a);

	a->x /= npoly;
	a->y /= npoly;
	a->z /= npoly;

	return a;
}
double dotM3(M3 *a, M3 *b)
{
	return a->x * b->x + a->y * b->y + a->z * b->z;
}
M3 *crossM3(M3 *a, M3 *b)
{
	M3 r;

	r.x = a->y*b->z-a->z*b->y;
	r.y = a->z*b->x-a->x*b->z;
	r.z = a->x*b->y-a->y*b->x;

	*a = r;

	return a;
}
M3 *subM3(M3 *a, M3 *b)
{
	a->x -= b->x;
	a->y -= b->y;
	a->z -= b->z;

	return a;
}
void mulM4M44(double a[], double s[][4])
{
	double r[4];
	int i;

	for(i = 0; i < 4; i++)
		r[i] = s[0][i]*a[0] + s[1][i]*a[1] + s[2][i]*a[2] + s[3][i]*a[3];

	for(i = 0; i < 4; i++)
		a[i] = r[i];

	return;
}
void mulM44M44(double a[][4], double s[][4])
{
	double re[4][4];
	int r, c, n;

	for(r = 0; r < 4; r++)
		for(c = 0; c < 4; c++)
		{
			re[r][c] = 0;
			for(n = 0; n < 4; n++)
				re[r][c] += a[r][n]*s[n][c];
		}

	for(r = 0; r < 4; r++)
		for(c = 0; c < 4; c++)
			a[r][c] = re[r][c];

	return;
}
void setIdentM44(double a[][4])
{
	int i;

	for(i = 0; i < 4; i++)
	{
		a[i][0] = a[i][1] = a[i][2] = a[i][3] = 0;
		a[i][i] = 1;
	}

	return;
}
void transposeM44(double a[][4])
{
	int r, c;

	for(r = 0; r < 3; r++)
		for(c = r + 1; c < 4; c++)
		{
			double t;

			t = a[c][r];
			a[c][r] = a[r][c];
			a[r][c] = t;
		}

	return;
}
void getViewM44(double viewM44[4][4], M3 *lookat, M3 *lookup, M3 *eye)
{
	M3 zaxis, xaxis, yaxis;

	zaxis = gconf.lookat;
	normalM3(subM3(&zaxis, &gconf.eye));

	xaxis = gconf.lookup;	// TODO: calculate automatic
	normalM3(crossM3(&xaxis, &zaxis));

	yaxis = zaxis;
	crossM3(&yaxis, &xaxis);

	//double viewM44[4][4];
	viewM44[0][0] = xaxis.x,                    viewM44[0][1] = yaxis.x,                    viewM44[0][2] = zaxis.x,                    viewM44[0][3] = 0;
	viewM44[1][0] = xaxis.y,                    viewM44[1][1] = yaxis.y,                    viewM44[1][2] = zaxis.y,                    viewM44[1][3] = 0;
	viewM44[2][0] = xaxis.z,                    viewM44[2][1] = yaxis.z,                    viewM44[2][2] = zaxis.z,                    viewM44[2][3] = 0;
	viewM44[3][0] = -dotM3(&xaxis, &gconf.eye), viewM44[3][1] = -dotM3(&yaxis, &gconf.eye), viewM44[3][2] = -dotM3(&zaxis, &gconf.eye), viewM44[3][3] = 1;

	return;
}
void getPersM44(double persM44[4][4], double fov, double zn, double zf, double aspect)
{
	double fovY = fov * M_PI / 180;
	//double zn = 1;	// ZNear
	//double zf = 1000.0;	// ZFar
	double h = 1.0/tan(fovY/2);
	double w = h / aspect;/*((double)X.ww / X.wh)*/ /*1.0*//*<-aspect*/

	persM44[0][0] = w, persM44[0][1] = 0, persM44[0][2] = 0,              persM44[0][3] = 0;
	persM44[1][0] = 0, persM44[1][1] = h, persM44[1][2] = 0,              persM44[1][3] = 0;
	persM44[2][0] = 0, persM44[2][1] = 0, persM44[2][2] = zf/(zf-zn),     persM44[2][3] = 1;
	persM44[3][0] = 0, persM44[3][1] = 0, persM44[3][2] = -zn*zf/(zf-zn), persM44[3][3] = 0;

	return;
}

// http://marupeke296.com/DXG_No48_PointGroundInScreen.html
void screenToWorldM4(double a[4])
{
	double m[4][4], n[4][4];

	m[0][0] = X.ww / 2;	m[0][1] = 0;			m[0][2] = 0;	m[0][3] = 0;
	m[1][0] = 0;		m[1][1] = -X.wh / 2;	m[1][2] = 0;	m[1][3] = 0;
	m[2][0] = 0;		m[2][1] = 0;			m[2][2] = 1;	m[2][3] = 0;
	m[3][0] = X.ww / 2;	m[3][1] = X.wh / 2;		m[3][2] = 0;	m[3][3] = 1;
	invM44(m);

	getPersM44(n, gconf.fov, gconf.threedzn, gconf.threedzf, (double)X.ww / X.wh);
	//transposeM44(n);
	invM44(n);
	mulM44M44(m, n);

	getViewM44(n, &gconf.lookat, &gconf.lookup, &gconf.eye);
	//transposeM44(n);
	invM44(n);
	mulM44M44(m, n);

	//transposeM44(m);
	mulM4M44(a, m);
	//calc3D(a, m);
	a[0] /= a[3];
	a[1] /= a[3];
	a[2] /= a[3];
}
int getHitFloorM3(M3 *r, int x, int y)
{
	double a[4] = {x, y, 0, 1};
	double b[4] = {x, y, 1, 1};
	M3 s;

	screenToWorldM4(a);
	screenToWorldM4(b);

	r->x = b[0], r->y = b[1], r->z = b[2];
	 s.x = a[0],  s.y = a[1],  s.z = a[2];
	subM3(r, &s);
	normalM3(r);
	//DebugXprintf(0, 10, "%f %f %f %f", a[0], a[1], a[2], a[3]);
	s.x = -s.x, s.y = -s.y, s.z = -s.z;
	if(r->y <= 0)
	{
		M3 u = {0, 1, 0};
		double lr = dotM3(r, &u);
		double ln = dotM3(&s, &u);
		double co = ln / lr;
		r->x = -s.x + co * r->x;
		r->y = -s.y + co * r->y;
		r->z = -s.z + co * r->z;
		return TRUE;
	}else
		return FALSE;
}

int isShowableNode(struct tagNode *node)
{
	if(!node->parent)
		return TRUE;
	if(node->parent->parent)
		return TRUE;

	if(gconf.bundle > 0 && node->pingfail)
		return FALSE;
	if(gconf.bundle > 1 && !node->tracerouted)
		return FALSE;
	if(gconf.bundle > 2 && node->parent == &nroot && node->childs == 0)	// 1 hop node.
		return FALSE;

	return TRUE;
}

//void DebugXprintf(int x, int y, char *fmt, ...);
struct tagNode *getHitNodeFrom(int x, int y,  struct tagNode *node)
{
	int dest = gconf.nodeRadius;

	if(node == &nroot)
		dest = gconf.rootRadius;

	for(; node; node = node->next)
	{
		if(!isShowableNode(node))
			continue;

		if(distance(node->x, node->y, x, y) < dest)
			return node;

		if(node->child)
		{
			struct tagNode *ret;
			if((ret = getHitNodeFrom(x, y, node->child)) != NULL)
				return ret;
		}
	}

	return NULL;
}

struct tagNode *getHitNode(int x, int y)
{
	/*
	if(gconf.threed)
	{
		M3 r;
		if(!getHitFloorM3(&r, x + X.ww / 2, y + X.wh / 2))
			return NULL;
		x = r.x;
		y = r.z;
		//DebugXprintf(0, 10, "%f %f %f %f", a[0], a[1], a[2], a[3]);
	}
	*/

	return getHitNodeFrom(x, y, &nroot);
}

void trafficNode(in_addr_t sip, in_addr_t dip, int pktsize, int proto)
{
	struct tagNode *snode, *dnode;
	//int dotrace = TRUE;

	/*
	pthread_mutex_lock(&pmTraces);
	if(ctraces)
		dotrace = FALSE;
	pthread_mutex_unlock(&pmTraces);
	*/

	if(gconf.autonode)
	{
		pthread_mutex_lock(&pmNodes);
		snode = getOrAppendNode(sip, gconf.autotrace);
		dnode = getOrAppendNode(dip, gconf.autotrace);
		pthread_mutex_unlock(&pmNodes);
	}else
	{
		snode = searchNodeByIP(sip);
		dnode = searchNodeByIP(dip);
	}

	if(snode && dnode)
	{
		struct tagNode *node;

		for(node = snode; node; node = node->parent)
			node->upbyte += pktsize;
		for(node = dnode; node; node = node->parent)
			node->downbyte += pktsize;

		if(gconf.viewTraffic)
		{
			struct tagTraffic *traf;

			if((traf = malloc(sizeof(struct tagTraffic))) == NULL)
			{
				puts("Can't malloc traffic");
				abort();
			}else
			{
				struct tagNode *sn;

				traf->target = dnode;
				traf->pktsize = pktsize;
				traf->time = get_time();
				traf->isuplink = FALSE;
				traf->proto = proto;

				sn = snode;
				if(snode == &nroot)
				{
					traf->isuplink = TRUE;

					if((sn = searchNodeByIP(dnode->ip)) == NULL)
					{
						puts("traf-create: no child");
						abort();
					}
					while(sn && sn->parent != &nroot)
						sn = sn->parent;
					if(!sn)
					{
						puts("traf-create: no parent");
						abort();
					}
				}

				traf->next = sn->traffic;
				sn->traffic = traf;
			}
		}
	}

	return;
}

void packetHandler(u_char *lParam, const struct pcap_pkthdr *hdr, const u_char *data)
{
	struct ether_header *eth = (void*)data;

	gstat.packettv = hdr->ts;

	if(ntohs(eth->ether_type) == ETHERTYPE_IP)
	{
		struct ip *ip = (void*)(data + sizeof(struct ether_header));

		if(ip->ip_v == 4)
		{
			char *payload = NULL;
			int paylen = 0;

			//printf("%08X %08X\n", ntohl(ip->saddr), ntohl(ip->daddr));
			trafficNode(ip->ip_src.s_addr, ip->ip_dst.s_addr, ntohs(ip->ip_len), ip->ip_p);

			if(ip->ip_p == IPPROTO_TCP)
			{
				struct tcphdr *tcp = (void*)((char*)ip + sizeof(struct ip));
				int len = ntohs(ip->ip_len) - sizeof(struct ip) - sizeof(struct tcphdr);

				payload = (char*)tcp + sizeof(struct tcphdr);
				paylen = len;

				if(gconf.packetLog && len > 0)
				{
					char ts[256];
					int i;

					if(len > 16)
						len = 16;

					sprintf(ts, "TCP:%04X%04X:", ntohs(tcp->th_sport), ntohs(tcp->th_dport));

					for(i = 0; i < len; i++)
					{
						sprintf(ts, "%s%02X", ts, (unsigned int)(*(payload + i)) & 0xFF);
					}

					logstr(1, ts);
				}
			}
			if(ip->ip_p == IPPROTO_UDP)
			{
				struct udphdr *udp = (void*)((char*)ip + sizeof(struct ip));
				int len = ntohs(ip->ip_len) - sizeof(struct ip) - sizeof(struct udphdr);

				payload = (char*)udp + sizeof(struct udphdr);
				paylen = len;

				if(gconf.packetLog && len > 0)
				{
					char ts[256];
					int i;

					if(len > 16)
						len = 16;

					sprintf(ts, "UDP:%04X%04X:", ntohs(udp->uh_sport), ntohs(udp->uh_dport));

					for(i = 0; i < len; i++)
					{
						sprintf(ts, "%s%02X", ts, (unsigned int)(*(payload + i)) & 0xFF);
					}

					logstr(1, ts);
				}
			}
			if(ip->ip_p == IPPROTO_ICMP)
			{
				struct icmphdr *icmp = (void*)((char*)ip + sizeof(struct ip));
				int len = ntohs(ip->ip_len) - sizeof(struct ip) - 4/*type+code+cksum*/;

				payload = (char*)icmp + 4/*same as above*/;
				paylen = len;

				if(gconf.packetLog && len > 0)
				{
					char ts[256];
					int i;

					if(len > 16)
						len = 16;

					sprintf(ts, "ICM:%02X%02X----:", icmp->icmp_type, icmp->icmp_code);

					for(i = 0; i < len; i++)
					{
						sprintf(ts, "%s%02X", ts, (unsigned int)(*(payload + i)) & 0xFF);
					}

					logstr(1, ts);
				}
			}

			if(gconf.viewPacket && paylen > 0)
			{
				struct tagNode *node;

				pthread_mutex_lock(&pmNodes);

				if((node = searchNodeByIP(ip->ip_src.s_addr)) != NULL)
				{
					int i;

					for(i = 0; i < 3; i++)
						if(!node->packet[i])
							break;

					if(i < 3)
					{
						int j;
						char *p;

						node->packet[i] = malloc(12 + paylen*2 + 1);

						strcpy(node->packet[i], "            ");	// whitespace * 12

						p = node->packet[i] + 12;

						for(j = 0; j < paylen; j++)
						{
							sprintf(p, "%02X", (unsigned int)payload[j] & 0xFF);
							p += 2;
						}

						//puts(node->packet[i]);
						//printf("%d %d\n", 12 + paylen*2 + 1, p - node->packet[i]);

						node->packetptr[i] = node->packet[i];
					}
				}

				pthread_mutex_unlock(&pmNodes);
			}
		}
	}

	return;
}

void dumpTree(struct tagNode *node, int indentlv)
{
	int i;

	for(i = 0; i < indentlv; i++)
		printf(" ");

	if(!node->parent)
		printf("* childs: %d, leafs: %d\n", node->childs, node->leafs);
	else
		printf("* childs: %d, leafs: %d\n", node->parent->childs, node->parent->leafs);

	for(; node; node = node->next)
	{
		for(i = 0; i < indentlv; i++)
			printf(" ");

		printf(IPFMT" ping:%d", IPARG(node->ip), node->ping);
		if(node->name)
			printf(" (%s)", node->name);
		puts("");

		if(node->child)
			dumpTree(node->child, indentlv + 2);
	}

	return;
}

int getPingFromProbe(probe *p)
{
	return (p->recv_time - p->send_time) * 1000;	// msec
}

int traceIt(struct tagNode *targnode)
{
	sockaddr_any sa;
	probe p;
	int i, t = -1, hop;
	struct tagNode *node, *tnode = NULL; //, *pnode = NULL;
	//int ping;//, tping;

	if(icmp_sk == -1)
	{
		logstr(0, "Trace disabled (Rawsocket not initialized)");
		return 1;
	}

	if(!targnode)
		return 1;

	if(targnode->tracerouted)
	{
		logstrf(0, IPFMT" Already tracerouted!", IPARG(targnode->ip));
		return 1;
	}

	logstrf(0, "Trace "IPFMT" started!", IPARG(targnode->ip));

	sa.sa.sa_family = AF_INET;
	sa.sin.sin_addr.s_addr = targnode->ip;

	if(icmp_settarget(NULL, &sa, 1, 64))
	{
		puts("init err");
		return 1;
	}

	p.final = 0;
	p.err_str[0] = '\0';
	pthread_mutex_lock(&pmNodes);
	targnode->tracerouted = 1;
	pthread_mutex_unlock(&pmNodes);

	if(icmp_send_probe(&p, 255))
	{
		puts("sendfail on PING");
		pthread_mutex_lock(&pmNodes);
		targnode->pingfail = 1;
		pthread_mutex_unlock(&pmNodes);
		return 1;
	}
re:
	if(!dopoll(1, &p))
	{
		logstrf(0, "TIMEOUT: PING not return from "IPFMT, IPARG(targnode->ip));
		pthread_mutex_lock(&pmNodes);
		targnode->pingfail = 1;
		pthread_mutex_unlock(&pmNodes);
		return 1;
	}
	if(p.res.sin.sin_addr.s_addr != targnode->ip)
	{
		printf("PING MISMATCH: node is "IPFMT" but pong from "IPFMT"\n", IPARG(targnode->ip), IPARG(p.res.sin.sin_addr.s_addr));
		goto re;
	}
	if(!p.final)
	{
		logstrf(0, "TIME EXCEEDED: PING not return from "IPFMT, IPARG(targnode->ip));
		pthread_mutex_lock(&pmNodes);
		targnode->pingfail = 1;
		pthread_mutex_unlock(&pmNodes);
		return 1;
	}
	hop = suggestHop(p.rttl) + 1;

	node = targnode;
	pthread_mutex_lock(&pmNodes);
	node->ping = getPingFromProbe(&p);
	pthread_mutex_unlock(&pmNodes);

	logstrf(0, "Trace: "IPFMT" hop suggested %d(TTL:%d), ping %d (FROM: "IPFMT")", IPARG(node->ip), hop, p.rttl, node->ping, IPARG(p.res.sin.sin_addr.s_addr));

	for(i = hop; i > 0; i--)
	{
		p.final = 0;
		if(icmp_send_probe(&p, i))
		{
			puts("Send fail!");
			return 1;
		}
		if(dopoll(1, &p))
		{
			int gip = p.res.sin.sin_addr.s_addr;
			//const char *name;

			//if((name = addr2name(gip)) == NULL)
			//	;	//puts("Cannot resolve name!");

			logstrf(0, "%2d: [%s] delay:%f ttl:%d(sug-hop:%d) done:%d final:%d from:"IPFMT/*" > %s"*/
					, i, p.err_str, p.recv_time - p.send_time, p.rttl, suggestHop(p.rttl), p.done, p.final, IPARG(gip)/*, name*/);

			if(!p.final)
			{
				struct tagNode *newnode, *nparent;
				int last = 0;

				pthread_mutex_lock(&pmNodes);

				newnode = getOrAppendNode(gip, FALSE);
				if(newnode->tracerouted == 1)
					last = 1;

				if(newnode == node)	// BUG: direct self referenced node
				{
					newnode->parent = &nroot;
					newnode->pingfail = 1;
					pthread_mutex_unlock(&pmNodes);
					break;	// abort.
				}else
				{
					struct tagNode *pn;

					for(pn = newnode->parent; pn; pn = pn->parent)
						if(pn == node)
							break;
					if(pn)	// BUG: indirect self referenced node
					{	// TODO: Is it OK?(don't freeze?)
						newnode->parent = &nroot;
						newnode->pingfail = 1;
						pthread_mutex_unlock(&pmNodes);
						break;	// abort.
					}else
					{	// Nice node.
						nparent = node->parent;
						cutNode(node);
						appendChildTo(newnode, node);
						if(nparent != &nroot)	// will only when i>=hop.
						{
							for(pn = nparent; pn; pn = pn->parent)
								if(pn == newnode)
									break;
							if(!pn)
							{
								cutNode(newnode);
								appendChildTo(nparent, newnode);
							}
						}
					}
				}

				if(!newnode->resolved && gconf.autodns)
					resolveAdd(newnode);
				newnode->tracerouted = 1;
				newnode->ping = getPingFromProbe(&p);

				if(i >= hop)
				{
					if(t == -1)
					{
						logstr(0, "** Tracing Deep start");
						t = i;
						tnode = newnode;
					}
					logstr(0, "* Tracing Deep");
					i += 2;
				}else
				{
					node->ping = node->ping - newnode->ping;
					node = newnode;
				}

				pthread_mutex_unlock(&pmNodes);

				if(last)
					//logstr(0, "Trace complete.");
					break;
			}else
			{	// (p.final)
				if(i >= hop && t != -1)
				{
					logstr(0, "** Tracing Deep finish");
					i = t;
					// ping substracting
					while(node && node->parent && node != tnode)
					{
						node->ping = node->ping - node->parent->ping;
						node = node->parent;
					}
					if(!node || !node->parent)
					{
						puts("ABORT: node or node->parent");
						abort();
					}
					// here: node == tnode;
				}
			}

			// TODO:
			/*
			if(i >= hop)
			{
				if(!p.final)
				{
					puts("NOT final: tracing forward...");
					if(t == -1)
					{
						t = i;
						tping = ping;
						tnode = node;
					}
					i += 2;
				}else if(t != -1)
				{
					puts("OK, resuming.");
					i = t;
				}
			}
			*/
		}else
		{
			logstrf(0, "%2d: ***", i);
		}
		usleep(gconf.traceHopInterval);
	}

	return 0;
}

void *traceRunner(void *param)
{
	for(; ctraces;)
	{
		int i;
		struct tagNode *tracee;

		pthread_mutex_lock(&pmTraces);
		tracee = traces[0];
		ctraces--;
		for(i = 0; i < ctraces; i++)
			traces[i] = traces[i + 1];
		pthread_mutex_unlock(&pmTraces);

		if(tracee->tracerouted)
			continue;

		if(traceIt(tracee) == 0)
		{
			logstrf(0, "Trace "IPFMT" completed, remain %d.", IPARG(tracee->ip), ctraces);
			tracee->tradd = get_time();
		}else
		{
			logstrf(0, "Trace "IPFMT" failed, remain %d.", IPARG(tracee->ip), ctraces);
		}

		sleep(gconf.traceInterval);
	}

	logstr(0, "All tracing completed.");

	pthread_mutex_lock(&pmTraceRunner);
	pthTraceRunner = 0;
	pthread_mutex_unlock(&pmTraceRunner);

	pthread_exit(NULL);
	return 0;
}

void traceAdd(struct tagNode *node)
{
	int i;

	pthread_mutex_lock(&pmTraces);
	for(i = 0; i < ctraces; i++)
		if(traces[ctraces] == node)
		{
			pthread_mutex_unlock(&pmTraces);
			return;
		}

	traces = remalloc(traces, sizeof(*traces) * (ctraces + 1));
	traces[ctraces] = node;
	ctraces++;
	pthread_mutex_unlock(&pmTraces);

	pthread_mutex_lock(&pmTraceRunner);
	if(!pthTraceRunner)
	{
		if(pthread_create(&pthTraceRunner, NULL, traceRunner, NULL))
		{
			puts("Cannot create traceroute thread!!");
			pthread_mutex_unlock(&pmTraceRunner);
			return;
		}
		pthread_detach(pthTraceRunner);
	}
	pthread_mutex_unlock(&pmTraceRunner);

	return;
}

void freeRecursive(struct tagNode *node)
{
	while(node)
	{
		struct tagNode *tnext;

		if(node->name)
			free(node->name);

		if(node->child)
			freeRecursive(node->child);

		tnext = node->next;
		free(node);
		node = tnext;
	}

	return;
}

void freeAll(void)
{
	pthread_mutex_lock(&pmTraces);
	ctraces = 0;
	pthread_mutex_unlock(&pmTraces);
	if(pthTraceRunner)
	{
		logstr(0, "Please wait until trace ends...");
		while(pthTraceRunner)
			usleep(100000);
	}

	pthread_mutex_lock(&pmResolves);
	cresolves = 0;
	pthread_mutex_unlock(&pmResolves);
	if(pthResolveRunner)
	{
		logstr(0, "Please wait until resolve ends...");
		while(pthResolveRunner)
			usleep(100000);
	}

	pthread_mutex_lock(&pmNodes);
	freeRecursive(nroot.child);
	nroot.child = NULL;
	nroot.childs = 0;
	nroot.leafs = 0;
	pthread_mutex_unlock(&pmNodes);

	return;
}

double atofor(const char *str, double def)
{
	if(!str)return def;
	else	return atof(str);
}
long long int atollor(const char *str, long long int def)
{
	if(!str)return def;
	else	return atoll(str);
}

void showTwoNodeTrace(struct tagNode *node, struct tagNode *parent)
{
	struct tagNode *ln, *rn;
	int i, lmaxl = 0, rmaxl = 0, lc, rc, lm=0, rm=0;

	for(i = 0; i < 2; i++)
	{
		int j;

		if(i)
		{
			for(j = 0; j < lmaxl - 5; j++)	printf(" ");
			printf("EXIST NEW\n");
		}
		for(ln = node, rn = node, lc=rc=(lm>rm?lm:rm); ln || rn;)
		{
			int l;
			char ts[256];

			if(ln && (!i || lc <= lm))
			{
				if(ln->resolved && ln->name)l=sprintf(ts, "(%s) "IPFMT, ln->name, IPARG(ln->ip));
				else						l=sprintf(ts,        IPFMT,           IPARG(ln->ip));
				if(!i)
				{
					if(lmaxl < l)
						lmaxl = l;
				}else
				{
					for(j = 0; j < lmaxl - l; j++)	printf(" ");
					printf("%s ", ts);
				}
				ln=ln->parent;
			}else if(i)
			{
				for(j = 0; j < lmaxl + 1; j++)	printf(" ");
			}
			if(rn && (!i || rc <= rm))
			{
				if(rn->resolved && rn->name)l=sprintf(ts, IPFMT" (%s)", IPARG(rn->ip), rn->name);
				else						l=sprintf(ts, IPFMT       , IPARG(rn->ip));
				if(!i)
				{
					if(rmaxl < l)
						rmaxl = l;
				}else
				{
					printf("%s", ts);
				}
				rn=rn->parent;
			}
			if(i) puts("");

			if(lc==lm)ln=parent;
			if(!i)
			{
				if(ln)	lc++;
				if(rn)	rc++;
			}else
			{
				lc--;
				rc--;
			}
		}
		lm = lc, rm = rc;
	}
}

void loadRecursive(FILE *fp, struct tagNode *parent, int merge)
{
	struct tagNode **ppnode = &parent->child;

	{
		double rat;
		char ts[64];
		int lts;

		rat = (double)ftell(fp) / gstat.fsize;

		lts = sprintf(ts, "Loading nodes... %6.2f%% %c", rat * 100, loadchar[gstat.phase]);
		XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);
		XFillRectangle(X.disp, X.wnd, X.gcStripe, 50 + 4, X.wh - 100 + 4, (double)(X.ww - 50 - 4 - (50 + 4))*rat, 50 - 4 - 4);
		XSync(X.disp, FALSE);

		//usleep(10000);

		gstat.phase = (gstat.phase + 1) % 4;
	}

	while(!feof(fp))
	{
		char buf[1024];
		char type;
		struct tagNode *node = NULL;
		int ip, found = FALSE, illegal = FALSE;

		fgets(buf, 1024, fp);
		type = strtok(buf, " ")[0];

		if(type == 'X')	// End
			break;

		ip = (u_int32_t)htonl(strtoul(strtok(NULL, " "), NULL, 16));
		if(ip == 0 || ip == 0xFFFFFFFF)
		{
			continue;
		}

		if(merge)
		{
			node = searchNodeByIP(ip);
			found = node ? TRUE : FALSE;

			if(node)
			{
				if(node->parent != parent)
				{
					printf(IPFMT" parent is "IPFMT", not "IPFMT"!\n", IPARG(node->ip), IPARG(node->parent->ip), IPARG(parent->ip));
					//showTwoNodeTrace(node, parent);
					// TODO: add retrace queue
					//abort();
					{
						struct tagNode *p;
						int ppc, ppl;
						p = node->parent;
						printf("c%d l%d: ", node->childs, node->leafs);
						printf("c%d l%d->", node->parent->childs, node->parent->leafs);
						if(node->parent->parent)
							ppc = node->parent->parent->childs, ppl = node->parent->parent->leafs;
						cutNode(node);
						printf("c%d l%d", node->parent->childs, node->parent->leafs);
						if(!p->childs)
						{
							printf(", Parent "IPFMT" lose all child", IPARG(p->ip));
							if(node->parent->parent)
								printf("(pp: c%d>%d l%d>%d)", ppc, node->parent->parent->childs, ppl, node->parent->parent->leafs);
						}
						printf("\n");
					}
					appendChildTo(&nroot, node);
					node->tracerouted = 0;
					illegal = TRUE;
				}
			}
		}

		/*
		if(node)
			printf("node %d.%d.%d.%d exist\n", IPARG(ip));
		else
			printf("node %d.%d.%d.%d new\n", IPARG(ip));
		*/

		if(!node)
		{
			if((node = newNode(parent, 0)) == NULL)
			{
				if(!merge)
					freeAll();
				return;
			}

			node->ip = ip;
			node->name = strtok(NULL, " ");
			if(!strcmp(node->name, "?"))
			{
				node->name = NULL;
				if(gconf.autodns)
					resolveAdd(node);
			}else
			{
				node->resolved = TRUE;
				if(!strcmp(node->name, "*"))
					node->name = NULL;
				else
					node->name = strdup(node->name);
			}
			node->ping = atoi(strtok(NULL, " "));
			node->tracerouted = atoi(strtok(NULL, " "));
			node->pingfail = atoi(strtok(NULL, " "));
			if(!merge)
				node->tradd = atofor(strtok(NULL, " "), 0.0);
			else
			{
				node->tradd = get_time();
				strtok(NULL, " ");	// drop non-need field
			}
			node->upbyte = atollor(strtok(NULL, " "), 0);
			node->downbyte = atollor(strtok(NULL, " "), 0);

			node->x = nroot.x;
			node->y = nroot.y;

			//if(parent == &nroot && !node->tracerouted)
			//	traceAdd(node);

			if(type == 'L')	// Leaf
			{
				struct tagNode *np;

				parent->childs++;
				for(np = parent; np; np = np->parent)
					np->leafs++;
			}
		}

		if(type == 'N')	// Node
		{
			loadRecursive(fp, node, merge);
			if(!merge || !found)
				parent->childs++;
		}

		if(!illegal)
		{
			if(*ppnode && node->parent->child != node)
			{
				if(found)
				{
					struct tagNode *pnode;

					for(pnode = node->parent->child; pnode; pnode = pnode->next)
						if(pnode->next == node)
							break;

					// do not use cutNode here, it will decrease childs/leafs!
					pnode->next = node->next;	// cutout then
				}

				node->next = *ppnode;	// attach
			}
			*ppnode = node;

			ppnode = &node->next;
		}
	}

	return;
}

void doLoad(const char *fname, int anodeon, int merge)
{
	FILE *fp;

	if(!merge)
		freeAll();

	if(!fname || !fname[0])
		fname = "ngdump.txt";

	if(!(fp = fopen(fname, "r")))
	{
		logstrf(0, "Cannot open file '%s' to read", fname);
		return;
	}
	{
		struct stat st;
		if(stat(fname, &st))
		{
			logstrf(0, "Cannot stat file '%s'", fname);
			fclose(fp);
			return;
		}
		gstat.fsize = st.st_size;
		gstat.phase = 0;
	}

	XSetForeground(X.disp, X.gc, gconf.colorPx);
	XFillRectangle(X.disp, X.wnd, X.gc, 50, X.wh - 100, X.ww - 50 - 50, 50);
	XSetForeground(X.disp, X.gc, BlackPixel(X.disp, 0));
	XFillRectangle(X.disp, X.wnd, X.gc, 50 + 2, X.wh - 100 + 2, X.ww - 50 - 2 - (50 + 2), 50 - 2 - 2);
	XSetForeground(X.disp, X.gc, gconf.colorPx);

	XSetForeground(X.disp, X.gcStripe, gconf.colorPx);

	pthread_mutex_lock(&pmNodes);
	loadRecursive(fp, &nroot, merge);
	pthread_mutex_unlock(&pmNodes);
	fclose(fp);

	{
		const char *s = "";

		if(anodeon)
			gconf.autonode = TRUE;
		else
			s = " (autonode untouched)";

		if(!merge)
			logstrf(0, "Load completed.%s", s);
		else
			logstr(0, "Merge completed.");	// merge will anon=off
	}

	return;
}

void saveRecursive(FILE *fp, struct tagNode *node)
{
	for(; node; node = node->next)
	{
		char *name = node->name;

		if(!name)
			name = "*";
		if(!node->resolved)
			name = "?";

		fprintf(fp, "%c %08X %s %d %d %d %f %" PRIu64 " %" PRIu64 "\n"
				, node->child ? 'N' : 'L'
				, ntohl(node->ip)
				, name
				, node->ping
				, node->tracerouted
				, node->pingfail
				, node->tradd
				, node->upbyte
				, node->downbyte
			   );

		if(node->child)
			saveRecursive(fp, node->child);
	}
	fputs("X\n", fp);

	return;
}

void doSave(const char *fname)
{
	FILE *fp;

	if(!fname || !fname[0])
		fname = "ngdump.txt";

	if(!(fp = fopen(fname, "w")))
	{
		logstrf(0, "Cannot open file '%s' to write", fname);
		return;
	}
	pthread_mutex_lock(&pmNodes);
	saveRecursive(fp, nroot.child);
	pthread_mutex_unlock(&pmNodes);
	fclose(fp);

	logstr(0, "Save completed.");

	return;
}

void setRootPos(int x, int y)
{
	nroot.x = nroot.posinfo.x = nroot.posinfo.px = x;
	nroot.y = nroot.posinfo.y = nroot.posinfo.py = y;

	return;
}

void jumpTo(struct tagNode *node)
{
	if(!node)
		return;

	if(!gconf.threed)
	{
		// calcNodeXY
		setRootPos(-node->posinfo.x, -node->posinfo.y);
	}else
	{
		gconf.lookat.x = node->posinfo.x;
		gconf.lookat.y = 0;
		gconf.lookat.z = node->posinfo.y;
	}

	return;
}

void buildNetwork(struct tagNode *node, int ping, double astart, double aarea, int hops, struct tagNode *posparent, int draw);

void setCurNode(struct tagNode *node)
{
	double d;
	
	cnode = node;

	if(cnode)
	{
		switch(gconf.posmode)
		{
		case 0:
			if(cnode->parent)
			{
				// calcNodeXYPXY
				struct tagNode *p;

				p = node->parent;
				if(!p)
					p = &nroot;

				d = atan2(node->posinfo.py - p->posinfo.py, node->posinfo.px - p->posinfo.px) / 2 / M_PI;
			}
			else
				d = 0.0;
			break;
		case 1:
			// calcNodeD
			d = node->posinfo.deg;
			break;
		}

		if(gconf.autorotate)
		{
			gconf.rotate = d;//atan2(nroot.y - cnode->y, nroot.x - cnode->x) / 2 / M_PI;
			buildNetwork(&nroot, 0, 0.0, 1.0, 0, &nroot, FALSE);
		}
		if(gconf.autogo)
			jumpTo(node);
	}

	return;
}

// convenient funcs

// TODO isdigit
int isnumstr(const char *str)
{
	if(!str || !*str)
		return FALSE;

	for(; *str; str++)
	{
		if(*str < '0' || '9' < *str)
			return FALSE;
	}
	return TRUE;
}

int issignnumstr(const char *str)
{
	if(!str || !*str)
		return FALSE;

	if(*str == '-')
		str++;

	for(; *str; str++)
	{
		if(*str < '0' || '9' < *str)
			return FALSE;
	}
	return TRUE;
}

int isrealstr(const char *str)
{
	int point = FALSE;

	if(!str || !*str)
		return FALSE;

	if(*str == '-')
		str++;

	for(; *str; str++)
	{
		if(*str == '.')
		{
			if(!point)
			{
				point = TRUE;
				continue;
			}else
				return FALSE;
		}
		if(*str < '0' || '9' < *str)
			return FALSE;
	}
	return TRUE;
}

const char *strchrnonum(const char *str)
{
	if(!str)
		return NULL;

	for(; *str; str++)
		if(*str < '0' || '9' < *str)
			break;

	return str;
}

u_int32_t parseIPString(const char *str)
{
	char ts[4];
	const char *p;
	int i;
	u_int32_t ip = 0;

	if(!str || !*str)
	{
		errno = EINVAL;
		return 0;
	}

	for(i = 0; i < 4; i++)
	{
		u_int32_t n;

		p = strchrnonum(str);
		if(p == str || p - str > 3)
		{
			errno = EINVAL;
			return 0;	// length==0 is out, length>3 = value>999
		}
		if((i < 3 && *p != '.') || (i == 3 && (*p != ' ' && *p)))
		{
			errno = EINVAL;
			return 0;	// delimiter NOT '.' (and not terminated with ' ' or '\0')
		}
		strncpy(ts, str, p - str + 1);
		ts[p - str] = '\0';
		if((n = atoi(ts)) > 255)
		{
			errno = EINVAL;
			return 0;	// over 8bit
		}
		ip = (ip >> 8) | (n << 24);
		str = p + 1;
	}

	errno = 0;

	return ip;
}

int isipstr(const char *str)
{
	parseIPString(str);

	return errno ? FALSE : TRUE;
}

int getAsBool(const char *val)
{
	if(!strcmp(val, "on") || !strcmp(val, "yes") || !strcmp(val, "t"))
		val = "1";
	if(!strcmp(val, "off") || !strcmp(val, "no") || !strcmp(val, "f"))
		val = "0";
	if(isnumstr(val))
	{
		return atoi(val) ? 1 : 0;
	}

	return -1;
}

const char *getTimeString(struct timeval *tv)
{
	static char ts[256];
	//time_t t;
	struct tm *tm;
	double n;

	tm = localtime(&tv->tv_sec);
	n = get_time_double(tv);

	sprintf(ts, "%04d/%02d/%02d %02d:%02d:%02d.%06d"
			,tm->tm_year + 1900
			,tm->tm_mon + 1
			,tm->tm_mday
			,(int)(n / 60 / 60) % 24
			,(int)(n / 60) % 60
			,(int)n % 60
			,(int)((n - (int)n) * 1000000)
		   );

	return ts;
}
const char *getNowTimeString(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return getTimeString(&tv);
}

int setLoglines(int logid, const char *logdesc, int lines)
{
	struct tagLog *log = &logs[logid];

	if(lines >= 0)
	{
		pthread_mutex_lock(&log->pmLog);

		if(log->lines == lines)
		{
			pthread_mutex_unlock(&log->pmLog);
			logstrf(0, "%s lines already %d.", logdesc, lines);
		}else
		{
			log->log = remalloc(log->log, lines * sizeof(char*));
			if(log->lines < lines)
			{
				int i;

				for(i = log->lines; i < lines; i++)
					log->log[i] = NULL;
			}
			log->lines = lines;

			pthread_mutex_unlock(&log->pmLog);
			logstrf(0, "%s lines set to %d.", logdesc, lines);
		}

		return TRUE;
	} else
		return FALSE;
}

// cmds

int cmdLimit(int argc, char **argv)
{
	if(argc == 1)
	{
		if(gconf.maxhop)
			logstrf(0, "limit = %d", gconf.maxhop);
		else
			logstr(0, "limit = unlimited");
	} else
	{
		if(isnumstr(argv[1]))
		{
			gconf.maxhop = atoi(argv[1]);

			if(gconf.maxhop < 0)
				gconf.maxhop = 0;

			if(gconf.maxhop)
				logstrf(0, "limit set to %d.", gconf.maxhop);
			else
				logstr(0, "limit unset.");
		}else
			return 1;
	}

	return 0;
}
int cmdMarkpure(int argc, char **argv)
{
	if(!cnode)
		logstr(0, "None node selected");
	else
	{
		cnode->parent = &nroot;
		cnode->tracerouted = FALSE;
		cnode->pingfail = FALSE;
		cnode->marked = FALSE;
		logstrf(0, "Node "IPFMT" mark pure.", IPARG(cnode->ip));
	}

	return 0;
}
int cmdSave(int argc, char **argv)
{
	doSave(argv[1]);	// NULL or str.

	if(!strcmp(argv[0], "wq"))
		gstat.quitting = TRUE;

	return 0;
}
int cmdLoad(int argc, char **argv)
{
	int anon = TRUE;

	if(argv[0][strlen(argv[0]) - 1] == '!')
		anon = FALSE;

	doLoad(argv[1], anon, FALSE);

	return 0;
}
int cmdClearall(int argc, char **argv)
{
	freeAll();
	nroot.marked = FALSE;

	return 0;
}
int cmdQuit(int argc, char **argv)
{
	gstat.quitting = TRUE;

	return 0;
}
int cmdPosmode(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "posmode = %s", gconf.posmode ? "relative" : "absolute");
	}else
	{
		if(!strcmp(argv[1], "absolute") || !strcmp(argv[1], "a"))
		{
			gconf.posmode = 0;
			logstr(0, "Position mode absolute.");
		} else
		if(!strcmp(argv[1], "relative") || !strcmp(argv[1], "r"))
		{
			gconf.posmode = 1;
			logstr(0, "Position mode relative.");
		} else
			return 1;
	}

	return 0;
}
int cmdMovemode(int argc, char **argv)
{
	if(argc == 1)
	{
		if(gconf.movemode == -1)
			logstr(0, "movemode = level");
		if(gconf.movemode == 0)
			logstr(0, "movemode = atonce");
		if(gconf.movemode > 1)
			logstrf(0, "movemode = %d", gconf.movemode);
	}else
	{
		const char *param = argv[1];

		if(isnumstr(param))
		{
			gconf.movemode = atoi(param);

			if(gconf.movemode == 0)
				param = "level";
			if(gconf.movemode == 1)
				param = "atonce";
			if(gconf.movemode > 1)
			{
				logstrf(0, "Move mode set to %d.", gconf.movemode);
				return 0;
			}
		}
		if(!strcmp(param, "level"))
		{
			gconf.movemode = -1;
			logstr(0, "Move mode set to level.");
			return 0;
		} else
		if(!strcmp(param, "atonce"))
		{
			gconf.movemode = 0;
			logstr(0, "Move mode set to atonce.");
			return 0;
		} else
			return 1;
	}

	return 0;
}
int cmdCls(int argc, char **argv)
{
	int i;

	for(i = 0; i < logs[0].lines; i++)
	{
		if(logs[0].log[i])
		{
			free(logs[0].log[i]);
			logs[0].log[i] = NULL;
		}
	}

	return 0;
}
int cmdLoglines(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "loglines = %d", logs[0].lines);
		logstrf(0, "packet loglines = %d", logs[1].lines);
	}else
	{
		if(argc >= 2)
		{
			if(isnumstr(argv[1]))
			{
				if(!setLoglines(0, "Log", atoi(argv[1])))
					return 1;
			} else
			if(!!strcmp(argv[1], "-"))
				return 1;
		}
		if(argc >= 3)
		{
			if(isnumstr(argv[2]))
			{
				if(!setLoglines(1, "Packet log", atoi(argv[2])))
					return 1;
			} else
				return 1;
		}
	}

	return 0;
}
int cmdMinping(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "Ping min = %d", gconf.minping);
	}else
	{
		if(issignnumstr(argv[1]))
		{
			gconf.minping = atoi(argv[1]);
			logstrf(0, "Ping min set to %d.", gconf.minping);
		} else
			return 1;
	}

	return 0;
}
int cmdMaxping(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "Ping max = %d", gconf.maxping);
	}else
	{
		if(issignnumstr(argv[1]))
		{
			gconf.maxping = atoi(argv[1]);
			logstrf(0, "Ping max set to %d.", gconf.maxping);
		} else
			return 1;
	}

	return 0;
}
int cmdTraceall(int argc, char **argv)
{
	if(argc == 1)
	{
		int count;
		struct tagNode *node;

		for(count = 0, node = nroot.child; node; node = node->next)
		{
			if(!node->tracerouted)
				count++;
		}

		if(count > 0)
		{
			logstrf(0, "%d non-traced node exists. This command will make huge traffic.", count);
			logstr (0, "If you REALLY want to do, run 'traceall Go'.");
		}else
			logstr(0, "All nodes tracerouted.");
	}else
	{
		if(!strcmp(argv[1], "Go"))
		{
			struct tagNode *node;

			for(node = nroot.child; node; node = node->next)
			{
				if(!node->tracerouted)
					traceAdd(node);
			}
		} else
			return 1;
	}

	return 0;
}
int cmdDump(int argc, char **argv)
{
	pthread_mutex_lock(&pmNodes);

	dumpTree(&nroot, 0);
	puts("Dump OK");

	pthread_mutex_unlock(&pmNodes);

	return 0;
}
int cmdTraceinterval(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "traceInterval = %d sec", gconf.traceInterval);
		logstrf(0, "traceHopInterval = %d usec", gconf.traceHopInterval);
	}else
	{
		if(argc >= 2)
		{
			if(isnumstr(argv[1]))
			{
				gconf.traceInterval = atoi(argv[1]);
				logstrf(0, "Trace interval per host set to %d sec.", gconf.traceInterval);
			} else
			if(!!strcmp(argv[1], "-"))
				return 1;
		}
		if(argc >= 3)
		{
			if(isnumstr(argv[2]))
			{
				gconf.traceHopInterval = atoi(argv[2]) * 100000;
				logstrf(0, "Trace interval per hop set to %d usec.", gconf.traceHopInterval);
			} else
				return 1;
		}
	}

	return 0;
}
int cmdRemain(int argc, char **argv)
{
	logstrf(0, "Remain of traces: %d", ctraces);
	logstrf(0, "Remain of resolves: %d", cresolves);

	return 0;
}
int cmdClock(int argc, char **argv)
{
	if(argc == 1)
	{
		switch(gconf.clock)
		{
		case 0:	logstr(0, "clock = none");	break;
		case 1:	logstr(0, "clock = sec");	break;
		case 2:	logstr(0, "clock = wall");	break;
		}
	}else
	{
		if(!strcmp(argv[1], "now"))
		{
			logstr(0, getNowTimeString());
		} else
		if(!strcmp(argv[1], "none"))
		{
			gconf.clock = 0;
			logstr(0, "Clock type set to none.");
		} else
		if(!strcmp(argv[1], "sec"))
		{
			gconf.clock = 1;
			logstr(0, "Clock type set to sec.");
		} else
		if(!strcmp(argv[1], "wall"))
		{
			gconf.clock = 2;
			logstr(0, "Clock type set to wall.");
		} else
			return 1;
	}

	return 0;
}
int cmdRadius(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "nodeRadius = %d", gconf.nodeRadius);
		logstrf(0, "rootRadius = %d", gconf.rootRadius);
	}else
	{
		if(argc >= 2)
		{
			if(isnumstr(argv[1]))
			{
				gconf.nodeRadius = atoi(argv[1]);
				logstrf(0, "Radius of host set to %d.", gconf.nodeRadius);
			} else
			if(!!strcmp(argv[1], "-"))
				return 1;
		}
		if(argc >= 3)
		{
			if(isnumstr(argv[2]))
			{
				gconf.rootRadius = atoi(argv[2]);
				logstrf(0, "Radius of root set to %d.", gconf.rootRadius);
			} else
				return 1;
		}
	}

	return 0;
}
int cmdWindowsize(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "windowsize = %d x %d", X.ww, X.wh);
	}else
	{
		if(argc == 2 && !strcmp(argv[1], "full"))
		{
			XWindowAttributes att;
			int w, h;

			XGetWindowAttributes(X.disp, DefaultRootWindow(X.disp), &att);
			w = att.width;
			h = att.height;
			XMoveResizeWindow(X.disp, X.wnd, 0, 0, w, h);
			XGetWindowAttributes(X.disp, X.wnd, &att);
			XMoveResizeWindow(X.disp, X.wnd, -att.x, -att.y, w, h);
		}else
		if(argc >= 3 && isnumstr(argv[1]) && isnumstr(argv[2]))
			XResizeWindow(X.disp, X.wnd, atoi(argv[1]), atoi(argv[2]));
		else
			return 1;
	}

	return 0;
}
int cmdColor(int argc, char **argv)
{
	struct tagPpcols
	{
		const char *name;
		const char *desc;
		char ** ppcol;
		ulong *pPx;
	} ppcols[] = {
		{"general",	"General",			&gconf.colorName,		&gconf.colorPx},
		{"tcp",		"TCP packet",		&gconf.protocolor.tcp,	&gconf.protocolor.tcpPx},
		{"udp",		"UDP packet",		&gconf.protocolor.udp,	&gconf.protocolor.udpPx},
		{"icmp",	"ICMP packet",		&gconf.protocolor.icmp,	&gconf.protocolor.icmpPx},
		{"ghl",		"GlobeHighlight",	&gconf.globehlcolor,	&gconf.globehlcolorPx},
		{"ggl",		"GlobeGrid",		&gconf.globegridcolor,	&gconf.globegridcolorPx},
		{"gil",		"GlobeCountryEdge",	&gconf.globeinterncolor,&gconf.globeinterncolorPx},
		{NULL,		NULL}
	};
	char **ppcol;
	ulong xc, *pPx;

	if(argc == 1)
	{
		int i;
		for(i = 0; ppcols[i].ppcol; i++)
			logstrf(0, "%s color = '%s'", ppcols[i].desc, *ppcols[i].ppcol);
	} else
	{
		ppcol = ppcols[0].ppcol;
		pPx = ppcols[0].pPx;

		if(argc == 3)
		{
			if(!strcmp(argv[2], "*"))
			{
				ppcol = NULL;
				pPx = NULL;
			}else
			{
				int i;
				for(i = 1; ppcols[i].ppcol; i++)	// skip first entry
				{
					if(!strcmp(argv[2], ppcols[i].name))
					{
						ppcol = ppcols[i].ppcol;
						pPx = ppcols[i].pPx;
						break;
					}
				}
			}
		}
		if((xc = GetColor(X.disp, argv[1])) == -1)
			logstrf(0, "Color '%s' is invalid.", argv[1]);
		else
		{
			if(ppcol)
			{
				free(*ppcol);
				*ppcol = strdup(argv[1]);
				*pPx = xc;
				logstrf(0, "Color set to '%s'.", *ppcol);
			}else
			{
				int i;
				for(i = 0; ppcols[i].ppcol; i++)
				{
					ppcol = ppcols[i].ppcol;
					pPx = ppcols[i].pPx;
					free(*ppcol);
					*ppcol = strdup(argv[1]);
					*pPx = xc;
				}
				logstrf(0, "Color all set to '%s'.", argv[1]);
			}
		}
	}
	return 0;
}
int cmdMerge(int argc, char **argv)
{
	doLoad(argv[1], FALSE, TRUE);

	return 0;
}
int cmdRootat(int argc, char **argv)
{
	if(argc == 1)
	{	// place root center.
		setRootPos(0, 0);
	} else
	if(argc == 3)
	{
		if(isnumstr(argv[1]) && isnumstr(argv[2]))
		{
			setRootPos(atoi(argv[1]), atoi(argv[2]));
		}else
			return 1;
	} else
		return 1;

	return 0;
}
int cmdGo(int argc, char **argv)
{
	struct tagNode *node;

	if(argc == 1)
	{
		if((node = cnode) == NULL)
		{
			logstr(0, "No node selected!");
			return 0;
		}
	} else
	if(argc == 2)
	{
		if(isipstr(argv[1]))
		{
			u_int32_t ip = parseIPString(argv[1]);

			if((node = searchNodeByIP(ip)) == NULL)
			{
				logstrf(0, "Node IP="IPFMT" not found!", IPARG(ip));
				return 0;
			}
		}else
		{
			node = NULL;

			if(argv[0][strlen(argv[0]) - 1] == '!')
			{
				struct hostent *he;
				u_int32_t ip;

				if((he = gethostbyname(argv[1])) == NULL)
				{
					logstr(0, "Couldn't resolve name");
					return 1;
				}
				if(he->h_addrtype != AF_INET)
				{
					logstr(0, "Address not IPv4");
					return 1;
				}
				ip = *(u_int32_t*)he->h_addr_list[0];
				if((node = searchNodeByIP(ip)) == NULL)
				{
					logstrf(0, "Node Name=%s->IP="IPFMT" not found!", argv[1], IPARG(ip));
					return 0;
				}
			}

			if(!node && (node = searchNodeByName(argv[1])) == NULL)
			{
				logstrf(0, "Node Name=%s not found!", argv[1]);
				return 0;
			}
		}
	} else
		return 1;

	jumpTo(node);

	if(strcmp(argv[0], "gonsel"))
		setCurNode(node);

	return 0;
}
struct tagStat
{
	int nodes;
	int maxhop;

	int resolved;
	int traced;
	int pingfailed;

	int unsolvedcountry;
	int unknowncountry;
	int japan;
};
void cmdStat_inspectAll(struct tagStat *stat, struct tagNode *node, int hop)
{
	for(; node; node = node->next)
	{
		stat->nodes++;

		if(node->resolved)
			stat->resolved++;
		if(node->tracerouted)
			stat->traced++;
		if(node->pingfail)
			stat->pingfailed++;
		if(node->cityindex == -1)
			stat->unsolvedcountry++;
		if(node->cityindex == -2)
			stat->unknowncountry++;
		if(node->cityindex > -1 && !strcmp(gGlobe.cities[node->cityindex].country, "Japan"))
			stat->japan++;

		if(stat->maxhop < hop)
			stat->maxhop = hop;

		if(node->child)
			cmdStat_inspectAll(stat, node->child, hop + 1);
	}

	return;
}
int cmdStat_countChilds(struct tagNode *node)
{
	int total = 0;

	for(; node; node = node->next)
	{
		total += node->childs;

		if(node->child)
			total += cmdStat_countChilds(node->child);
	}

	return total;
}
int cmdStat(int argc, char **argv)
{
	struct tagStat stat = {0};

	cmdStat_inspectAll(&stat, &nroot, 0);

	logstr (0, "*** STATISTICS ***");
	logstr (0, "=== Total ===");
	logstrf(0, "nodes       : %d", stat.nodes);
	logstrf(0, "maxhop      : %d hop", stat.maxhop);
	logstrf(0, "NameResolved: %d (%.2f%% of total)", stat.resolved, (double)stat.resolved / stat.nodes * 100.0);
	logstrf(0, "Traced      : %d (%.2f%% of total)", stat.traced, (double)stat.traced / stat.nodes * 100.0);
	logstrf(0, "Pingfails   : %d (%.2f%% of total)", stat.pingfailed, (double)stat.pingfailed / stat.nodes * 100.0);
	logstrf(0, "UnsolCountry: %d (%.2f%% of total)", stat.unsolvedcountry, (double)stat.unsolvedcountry / stat.nodes * 100.0);
	logstrf(0, "UnknoCountry: %d (%.2f%% of total)", stat.unknowncountry, (double)stat.unknowncountry / stat.nodes * 100.0);
	logstrf(0, "JapanCountry: %d (%.2f%% of total)", stat.japan, (double)stat.japan / stat.nodes * 100.0);
	logstr (0, "=== Selected node ===");
	if(!cnode)
	{
		logstr (0, " No selection, omitted.");
	}else
	{
		logstrf(0, "Pos      : %d, %d", cnode->x, cnode->y);
		logstrf(0, "IP       : "IPFMT, IPARG(cnode->ip));
		logstrf(0, "Name     : %s", !cnode->resolved ? "(isn't resolved yet)" : !cnode->name ? "(can't resolve)" : cnode->name);
		logstrf(0, "Children : %d", cnode->childs);
		{
			int chs = cmdStat_countChilds(cnode) + 1/*<-self*/;
			logstrf(0, "Family   : %d (%.2f%% of total)", chs, (double)chs / stat.nodes * 100.0);
		}
		logstrf(0, "End-nodes: %d", cnode->leafs);
		if(!cnode->pingfail)
			logstrf(0, "Ping     : %d", cnode->ping);
		else
			logstr (0, "Ping     : failed");
		logstrf(0, "Up       : %lld bytes", cnode->upbyte);
		logstrf(0, "Down     : %lld bytes", cnode->downbyte);
	}

	return 0;
}
int cmdAddhost(int argc, char **argv)
{
	if(argc != 2)
	{
		return 1;
	}else
	{
		u_int32_t ip;

		if(!isipstr(argv[1]))
		{
			struct hostent *he;

			if((he = gethostbyname(argv[1])) == NULL)
			{
				logstr(0, "Couldn't resolve name");
				return 1;
			}
			if(he->h_addrtype != AF_INET)
			{
				logstr(0, "Address not IPv4");
				return 1;
			}
			ip = *(u_int32_t*)he->h_addr_list[0];
		}else
		{
			ip = parseIPString(argv[1]);
		}

		if(searchNodeByIP(ip) != NULL)
		{
			logstrf(0, "Node "IPFMT" already exists.", IPARG(ip));
			return 0;
		}

		if(beChildNodeOf(ip, &nroot, gconf.autodns) == NULL)
			logstrf(0, "ERROR: Couldn't add new node "IPFMT, IPARG(ip));
		else
			logstrf(0, "Added new node "IPFMT" successfully.", IPARG(ip));
	}

	return 0;
}
int cmdSetping(int argc, char **argv)
{
	if(!cnode)
	{
		logstr(0, "No node selected!");
		return 0;
	}

	if(argc == 1)
	{
		logstrf(0, "Node ping = %d", cnode->ping);
	}
	else
	{
		if(isnumstr(argv[1]))
		{
			cnode->ping = atoi(argv[1]);
			logstrf(0, "Set node ping %d.", cnode->ping);
		}else
			return 1;
	}

	return 0;
}
int cmdFlush(int argc, char **argv)
{
	int fTrace = FALSE, fResolve = FALSE;
	if(argc == 1)
	{
		fTrace = TRUE;
		fResolve = TRUE;
	}else if(argc == 2)
	{
		if(!strcmp(argv[1], "trace"))
			fTrace = TRUE;
		else
		if(!strcmp(argv[1], "resolve"))
			fResolve = TRUE;
		else
			return 1;
	} else
		return 1;

	if(fTrace)
	{
		if(ctraces)
		{
			pthread_mutex_lock(&pmTraces);
			ctraces = 0;
			pthread_mutex_unlock(&pmTraces);
			logstr(0, "Trace queue flushed.");
		}else
			logstr(0, "Trace queue already empty!");
	}
	if(fResolve)
	{
		if(cresolves)
		{
			pthread_mutex_lock(&pmResolves);
			cresolves = 0;
			pthread_mutex_unlock(&pmResolves);
			logstr(0, "Resolve queue flushed.");
		}else
			logstr(0, "Resolve queue already empty!");
	}

	return 0;
}
void parseCmd(const char *str);
int cmdSource(int argc, char **argv)
{
	if(argc != 2)
		return 1;

	{
		FILE *fp;

		if((fp = fopen(argv[1], "r")) == NULL)
		{
			logstrf(0, "Couldnot open file '%s' as script.", argv[1]);
			return 0;
		}
		while(!feof(fp))
		{
			char ts[1024];

			fgets(ts, sizeof(ts), fp);
			if(ts[strlen(ts) - 1] == '\n')
				ts[strlen(ts) - 1] = '\0';
			parseCmd(ts);
		}
		fclose(fp);

		logstr(0, "Source completed.");
	}

	return 0;
}
int nsckRecursive(struct tagNode *node)
{
	struct tagNode *n;
	int childs = 0, leafs = 0;
	int sanity = TRUE;

	for(n = node->child; n; n = n->next)
	{
		childs++;
		if(!n->child)
			leafs++;
		leafs += nsckRecursive(n);
	}

	if(node->childs != childs)
	{
		sanity = FALSE;
		printf("nsck: Node "IPFMT" childs=%d but true is %d\n", IPARG(node->ip), node->childs, childs);
		node->childs = childs;
	}
	if(node->leafs != leafs)
	{
		sanity = FALSE;
		printf("nsck: Node "IPFMT" leafs=%d but true is %d\n", IPARG(node->ip), node->leafs, leafs);
		node->leafs = leafs;
	}

	if(!sanity)
	{
		node->pingfail = TRUE;
		node->marked = TRUE;
	}

	return leafs;
}
int cmdNsck(int argc, char **argv)
{
	nsckRecursive(&nroot);
	return 0;
}
int cmdLookat(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "lookat=%f,%f,%f", gconf.lookat.x, gconf.lookat.y, gconf.lookat.z);
	}else if(argc == 4)
	{
		if(isrealstr(argv[1]) && isrealstr(argv[2]) && isrealstr(argv[3]))
		{
			gconf.lookat.x = atof(argv[1]);
			gconf.lookat.y = atof(argv[2]);
			gconf.lookat.z = atof(argv[3]);
			logstrf(0, "Look at %f,%f,%f.", gconf.lookat.x, gconf.lookat.y, gconf.lookat.z);
		} else
			return 1;
	}else
		return 1;

	return 0;
}
int cmdLookup(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "lookup=%f,%f,%f", gconf.lookup.x, gconf.lookup.y, gconf.lookup.z);
	}else if(argc == 4)
	{
		if(isrealstr(argv[1]) && isrealstr(argv[2]) && isrealstr(argv[3]))
		{
			gconf.lookup.x = atof(argv[1]);
			gconf.lookup.y = atof(argv[2]);
			gconf.lookup.z = atof(argv[3]);
			logstrf(0, "Look up %f,%f,%f.", gconf.lookup.x, gconf.lookup.y, gconf.lookup.z);
		} else
			return 1;
	}else
		return 1;

	return 0;
}
int cmdEyeat(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "eyeat=%f,%f,%f", gconf.eye.x, gconf.eye.y, gconf.eye.z);
	}else if(argc == 4)
	{
		if(isrealstr(argv[1]) && isrealstr(argv[2]) && isrealstr(argv[3]))
		{
			gconf.eye.x = atof(argv[1]);
			gconf.eye.y = atof(argv[2]);
			gconf.eye.z = atof(argv[3]);
			logstrf(0, "Eye at %f,%f,%f.", gconf.eye.x, gconf.eye.y, gconf.eye.z);
		} else
			return 1;
	}else
		return 1;

	return 0;
}
void cmdResolveRecursive(struct tagNode *node)
{
	for(node = node; node; node = node->next)
	{
		if(!node->resolved)
			resolveAdd(node);
		if(node->child)
			cmdResolveRecursive(node->child);
	}
}
int cmdResolveall(int argc, char **argv)
{
	cmdResolveRecursive(&nroot);

	return 0;
}
int cmdBundle(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "bundle = %d", gconf.bundle);
	}else if(argc == 2)
	{
		if(isnumstr(argv[1]))
		{
			logstrf(0, "bundle set to %d.", gconf.bundle = atoi(argv[1]));
		}else
			return 1;
	}else
		return 1;

	return 0;
}
int cmdGlobe(int argc, char **argv)
{
	if(argc == 1)
	{
		logstrf(0, "globe = %d", gconf.globe);
	}else
	{
		int b = getAsBool(argv[1]);

		if(b > -1)
		{
			logstrf(0, "globe set to %d.", gconf.globe = b);

			if(b)
			{
				/*
				gconf.eye.x = 0;
				gconf.eye.y = 50;
				gconf.eye.z = 150;
				gconf.lookat.x = 100;
				gconf.lookat.y = 0;
				gconf.lookat.z = 0;
				*/
				gconf.fov = 60;
				gconf.threed = TRUE;
			}
		}
		else
			return 1;
	}

	return 0;
}

int cmdLoadmodel(int argc, char **argv)
{
	FILE *fp;
	char line[256];

	if(argc != 2)
	{
		logstr(0, "Only one argument need!");
		return 1;
	}

	if((fp = fopen(argv[1], "r")) == NULL)
	{
		logstrf(0, "File '%s' not found!", argv[1]);
		return 0;
	}

	if(gstat.model.points)
	{
		free(gstat.model.points);
		gstat.model.points = NULL;
		gstat.model.cpoints = 0;
	}
	if(gstat.model.lines)
	{
		free(gstat.model.lines);
		gstat.model.lines = NULL;
		gstat.model.clines = 0;
	}

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		char *type = strtok(line, " ");

		if(!strcmp(type, "v"))	// vertex
		{
			double x = atof(strtok(NULL, " "));
			double y = atof(strtok(NULL, " "));
			double z = atof(strtok(NULL, " "));

			gstat.model.points = remalloc(gstat.model.points, sizeof(*gstat.model.points) * (gstat.model.cpoints + 1));
			gstat.model.points[gstat.model.cpoints].x = x;
			gstat.model.points[gstat.model.cpoints].y = y;
			gstat.model.points[gstat.model.cpoints].z = z;
			gstat.model.cpoints++;
		}

		if(!strcmp(type, "f"))	// f(line)
		{
			int a = atoi(strtok(NULL, " ")) - 1;
			int b = atoi(strtok(NULL, " ")) - 1;

			gstat.model.lines = remalloc(gstat.model.lines, sizeof(*gstat.model.lines) * (gstat.model.clines + 1));
			gstat.model.lines[gstat.model.clines][0] = a;
			gstat.model.lines[gstat.model.clines][1] = b;
			gstat.model.clines++;
		}
	}

	fclose(fp);

	return 0;
}

int cmdHelp(int,char**);
int cmdBoolvar(int,char**);
int cmdUintvar(int,char**);
int cmdIntvar(int,char**);
int cmdFloatvar(int,char**);

struct tagCmdlist
{
	const char *cmd;
	int (*func)(int argc, char **argv);
	const char *desc;
	void *var;
} cmdlist[] = {
	{"help",			cmdHelp,			"help[!] .............................. : Show this help if loglines enough(help!: show help anyway)"},
	{"help!",			cmdHelp,			NULL},
	{"limit",			cmdLimit,			"limit [hops] ......................... : Limit network hops"},
	{"markpure",		cmdMarkpure,		"markpure ............................. : Mark current node NOT tracerouted"},
	{"save",			cmdSave,			"save[!] [filename] ................... : Save current network"},
	{"save!",			cmdSave,			NULL},
	{"w",				cmdSave,			NULL},
	{"w!",				cmdSave,			NULL},
	{"wq",				cmdSave,			NULL},
	{"wq!",				cmdSave,			NULL},
	{"load",			cmdLoad,			"load[!] [filename] ................... : Load previous network"},
	{"load!",			cmdLoad,			NULL},
	{"o",				cmdLoad,			NULL},
	{"o!",				cmdLoad,			NULL},
	{"e",				cmdLoad,			NULL},
	{"e!",				cmdLoad,			NULL},
	{"clearall",		cmdClearall,		"clearall[!] .......................... : Clear current network"},
	{"clearall!",		cmdClearall,		NULL},
	{"new",				cmdClearall,		NULL},
	{"new!",			cmdClearall,		NULL},
	{"quit",			cmdQuit,			"quit[!] .............................. : Quit this application"},
	{"quit!",			cmdQuit,			NULL},
	{"q",				cmdQuit,			NULL},
	{"q!",				cmdQuit,			NULL},
	{"posmode",			cmdPosmode,			"posmode ['a'['bsolute']|'r'['elative']]: Set the position mode"},
	{"pm",				cmdPosmode,			NULL},
	{"movemode",		cmdMovemode,		"movemode ['level'|'atonce'|value] .... : Set the moving coeffecient"},
	{"mm",				cmdMovemode,		NULL},
	{"cls",				cmdCls,				"cls .................................. : Clear the log"},
	{"loglines",		cmdLoglines,		"loglines [lines [lines]] ............. : Set log lines, and packet log's if specified."},
	{"ll",				cmdLoglines,		NULL},
	{"autodns",			cmdBoolvar,			"autodns [bool] ....................... : Auto resolve name",	&gconf.autodns},
	{"ad",				cmdBoolvar,			NULL},
	{"autotrace",		cmdBoolvar,			"autotrace [bool] ..................... : Auto traceroute",	&gconf.autotrace},
	{"at",				cmdBoolvar,			NULL},
	{"minping",			cmdMinping,			"minping [value] ...................... : Set min ping(drawing network)"},
	{"np",				cmdMinping,			NULL},
	{"maxping",			cmdMaxping,			"maxping [value] ...................... : Set max ping(drawing network)"},
	{"xp",				cmdMaxping,			NULL},
	{"logstdout",		cmdBoolvar,			"logstdout [bool] ..................... : Set log tee to stdout",	&gconf.logstdout},
	{"lso",				cmdBoolvar,			NULL},
	{"traceall",		cmdTraceall,		"traceall ............................. : Add all non-traced node to trace queue"},
	{"dump",			cmdDump,			"dump ................................. : Dump tree to stdout"},
	{"showinfo",		cmdBoolvar,			"showinfo [bool] ...................... : Show node's info",	&gconf.showinfo},
	{"si",				cmdBoolvar,			NULL},
	{"traceinterval",	cmdTraceinterval,	"traceinterval [sec [100usec]] ........ : Set trace interval per host by second, per hop by 100msecs"},
	{"tint",			cmdTraceinterval,	NULL},
	{"remain",			cmdRemain,			"remain ............................... : Show remain of Traces, Resolves."},
	{"clock",			cmdClock,			"clock ['none'|'wall'|'sec'] .......... : Set style of clock."},
	{"radius",			cmdRadius,			"radius [value [value]] ............... : Set radius of node, and root if specified."},
	{"rad",				cmdRadius,			NULL},
	{"viewpacket",		cmdBoolvar,			"viewpacket [bool] .................... : View packet of each node.",	&gconf.viewPacket},
	{"vp",				cmdBoolvar,			NULL},
	{"windowsize",		cmdWindowsize,		"windowsize ['full'|width height] ..... : Set window size width*height."},
	{"ws",				cmdWindowsize,		NULL},
	{"color",			cmdColor,			"color [name] [proto] ................. : Set foreground color. for detail, see X11's rgb.txt."},
	{"autonode",		cmdBoolvar,			"autonode [bool] ...................... : Auto add node with libpcap",	&gconf.autonode},
	{"an",				cmdBoolvar,			NULL},
	{"bundle",			cmdBundle,			"bundle [int] ......................... : 1:Bundle ping-failed nodes. 2:also not tracerouted nodes"},
	{"bu",				cmdBundle,			NULL},
	{"merge",			cmdMerge,			"merge [filename] ..................... : Merge previous network."},
	{"r",				cmdMerge,			NULL},
	{"rootat",			cmdRootat,			"rootat [value value] ................. : Root node position, place center if param omit."},
	{"go",				cmdGo,				"go[!] [(node ip or name)] ............ : Move specified node to center, selected node if param omit."},
	{"go!",				cmdGo,				NULL},
	{"gonsel",			cmdGo,				"gonsel [(node ip or name)] ........... : Same as go but don't select target."},
	{"viewtraffic",		cmdBoolvar,			"viewtraffic [bool] ................... : View traffic.",	&gconf.viewTraffic},
	{"vt",				cmdBoolvar,			NULL},
	{"autogo",			cmdBoolvar,			"autogo [bool] ........................ : Auto center select node",	&gconf.autogo},
	{"ag",				cmdBoolvar,			NULL},
	{"stat",			cmdStat,			"stat ................................. : Collect statistics."},
	{"packetlog",		cmdBoolvar,			"packetlog [bool] ..................... : Show packet log",	&gconf.packetLog},
	{"pl",				cmdBoolvar,			NULL},
	{"addhost",			cmdAddhost,			"addhost <name> ....................... : Add specified host."},
	{"ah",				cmdAddhost,			NULL},
	{"threed",			cmdBoolvar,			"threed [bool] ........................ : Show as pseudo-3D.",	&gconf.threed},
	{"3d",				cmdBoolvar,			NULL},
	{"setping",			cmdSetping,			"setping [ping] ....................... : FOR DEBUG: DO NOT USE."},
	{"flush",			cmdFlush,			"flush ['trace'|'resolve'] ............ : Flush queue of traces, or resolves."},
	{"rotate",			cmdFloatvar,		"rotate [degree] ...................... : Rotate graph.",	&gconf.rotate},
	{"rot",				cmdFloatvar,		NULL},
	{"autorotate",		cmdBoolvar,			"autorotate [bool] .................... : Auto rotate map.",	&gconf.autorotate},
	{"ar",				cmdBoolvar,			NULL},
	{"source",			cmdSource,			"source <filename> .................... : Exec file as command."},
	{".",				cmdSource,			NULL},
	{"nsck",			cmdNsck,			"nsck ................................. : FOR DEBUG: DO NOT USE."},
	{"fov",				cmdFloatvar,		"fov [fov] ............................ : Set camera Field Of View.",	&gconf.fov},
	{"lookat",			cmdLookat,			"lookat [x y z] ....................... : Set camera lookat."},
	{"lookup",			cmdLookup,			"lookup [x y z] ....................... : Set camera upside."},
	{"eyeat",			cmdEyeat,			"eyeat [x y z] ........................ : Set camera position."},
	{"resolveall",		cmdResolveall,		"resolveall ........................... : Add all non-resolved node to resolve queue"},
	{"rall",			cmdResolveall,		NULL},
	{"showpktsize",		cmdBoolvar,			"showpktsize [bool] ................... : Show packet size at each packets.",	&gconf.showpktsize},
	{"sps",				cmdBoolvar,			NULL},
	{"tgrid",			cmdBoolvar,			"tgrid [bool] ......................... : Show threeD grid.",	&gconf.threedgrid.enabled},
	{"tgintv",			cmdFloatvar,		"tgintv [float] ....................... : tgrid interval",	&gconf.threedgrid.interval},
	{"tgrad",			cmdFloatvar,		"tgrad [float] ........................ : tgrid radius",	&gconf.threedgrid.radius},
	{"tgsize",			cmdFloatvar,		"tgsize [float] ....................... : tgrid size of pivots",	&gconf.threedgrid.size},
	{"pktintv",			cmdFloatvar,		"pktintv [float] ...................... : Packet hop-to-hop interval",	&gconf.pktinterval},
	{"tdzn",			cmdFloatvar,		"tdzn [float] ......................... : threeD ZNear",	&gconf.threedzn},
	{"tdzf",			cmdFloatvar,		"tdzf [float] ......................... : threeD ZFar",	&gconf.threedzf},
	{"globe",			cmdGlobe,			"globe [bool] ......................... : Globe mode"},
	{"globeip",			cmdBoolvar,			"globeip [bool] ....................... : Show IP on globe",	&gconf.globeip},
	{"globerotdx",		cmdFloatvar,		"globerotdx [float] ................... : Globe rotation delta",	&gconf.globerotdx},
	{"globelh",			cmdFloatvar,		"globelh [float] ...................... : Globe node-to-node line height",	&gconf.globelineheight},
	{"globeldiv",		cmdUintvar,			"globeldiv [uint] ..................... : Globe node-to-node line resolution",	&gconf.globelinediv},
	{"globerad",		cmdFloatvar,		"globerad [float] ..................... : Globe radius",	&gconf.globerad},
	{"globehl",			cmdBoolvar,			"globehl [bool] ....................... : Globe node-to-node highlight",	&gconf.globehilight},
	{"restfps",			cmdUintvar,			"restfps [uint] ....................... : Restricts Frame Per Second.",	&gconf.restfps},
	{"pktdspcnt",		cmdIntvar,			"pktdspcnt [int] ...................... : Set pcap_dispatch's cnt.",	&gconf.pktdispatchcnt},
	{"pdc",				cmdIntvar,			NULL},
	{"globesom",		cmdBoolvar,			"globesom [bool] ...................... : Globe show only metrocity",	&gconf.globeshowonlymetro},
	{"loadmodel",		cmdLoadmodel,		"loadmodel filename ................... : Load model(OBJ format only!)"},

	{NULL,			NULL,			NULL}
};

int cmdHelp(int argc, char **argv)
{
	struct tagCmdlist *cmd;

	if(!(!strcmp(argv[0], "help!")))
	{
		int cmds;

		for(cmd = cmdlist, cmds = 0; cmd->cmd; cmd++)
		{
			if(cmd->desc)
				cmds++;
		}

		if(logs[0].lines < cmds + 2)
		{
			logstrf(0, "Log lines not enough. set loglimit at least %d.", cmds + 2);
			return 0;
		}
	}

	logstr(0, "== Help: "/*"<> is required, "*/"[] is optional, | is selectional parameter.");
	for(cmd = cmdlist; cmd->cmd; cmd++)
	{
		if(cmd->desc && cmd->desc[0])	// NULL=omit-cmd "\0"=hidden-cmd
			logstr(0, cmd->desc);
	}

	return 0;
}
int cmdBoolvar(int argc, char **argv)
{
	struct tagCmdlist *cl, *lcl;

	for(cl = cmdlist, lcl = NULL; cl; cl++)
	{
		if(!strcmp(cl->cmd, argv[0]))
		{
			if(!cl->desc)
				cl = lcl;
			break;
		}

		if(cl->desc)
			lcl = cl;
	}

	if(!cl)
		return 1;

	if(argc == 1)
	{
		logstrf(0, "%s = %d", cl->cmd, *(int*)cl->var);
	}else
	{
		int b = getAsBool(argv[1]);

		if(b > -1)
			logstrf(0, "%s set to %d.", cl->cmd, *(int*)cl->var = b);
		else
			return 1;
	}

	return 0;
}
int cmdFloatvar(int argc, char **argv)
{
	struct tagCmdlist *cl, *lcl;

	for(cl = cmdlist, lcl = NULL; cl; cl++)
	{
		if(!strcmp(cl->cmd, argv[0]))
		{
			if(!cl->desc)
				cl = lcl;
			break;
		}

		if(cl->desc)
			lcl = cl;
	}

	if(!cl)
		return 1;

	if(argc == 1)
	{
		logstrf(0, "%s = %f", cl->cmd, *(double*)cl->var);
	}else
	{
		if(isrealstr(argv[1]))
			logstrf(0, "%s set to %f.", cl->cmd, *(double*)cl->var = atof(argv[1]));
		else
			return 1;
	}

	return 0;
}
int cmdUintvar(int argc, char **argv)
{
	struct tagCmdlist *cl, *lcl;

	for(cl = cmdlist, lcl = NULL; cl; cl++)
	{
		if(!strcmp(cl->cmd, argv[0]))
		{
			if(!cl->desc)
				cl = lcl;
			break;
		}

		if(cl->desc)
			lcl = cl;
	}

	if(!cl)
		return 1;

	if(argc == 1)
	{
		logstrf(0, "%s = %u", cl->cmd, *(unsigned int*)cl->var);
	}else
	{
		if(isnumstr(argv[1]))
			logstrf(0, "%s set to %u.", cl->cmd, *(unsigned int*)cl->var = atoi(argv[1]));
		else
			return 1;
	}

	return 0;
}
int cmdIntvar(int argc, char **argv)
{
	struct tagCmdlist *cl, *lcl;

	for(cl = cmdlist, lcl = NULL; cl; cl++)
	{
		if(!strcmp(cl->cmd, argv[0]))
		{
			if(!cl->desc)
				cl = lcl;
			break;
		}

		if(cl->desc)
			lcl = cl;
	}

	if(!cl)
		return 1;

	if(argc == 1)
	{
		logstrf(0, "%s = %d", cl->cmd, *(int*)cl->var);
	}else
	{
		if(issignnumstr(argv[1]))
			logstrf(0, "%s set to %d.", cl->cmd, *(int*)cl->var = atoi(argv[1]));
		else
			return 1;
	}

	return 0;
}

void parseCmd(const char *str)
{
	const char *p, *pp;
	int argc;
	char **argv = NULL;

	if(!str)
		return;

	// make arg
	for(p = pp = str, argc = 0; p; pp = p)
	{
		int l;

		p = strchr(p, ' ');

		if(!p)
			l = strlen(pp);
		else
			l = p - pp, p++;

		argv = remalloc(argv, sizeof(char*) * (argc + 1));
		argv[argc++] = strndup(pp, l);
	}

	argv = remalloc(argv, sizeof(char*) * (argc + 1));
	argv[argc] = NULL;

	logstrf(0, ":%s", str);

	// search and call
	if(strlen(argv[0]))
	{
		struct tagCmdlist *cmd;

		for(cmd = cmdlist; cmd->cmd; cmd++)
		{
			if(!strcmp(argv[0], cmd->cmd))
			{
				if(cmd->func(argc, argv) == 0)
					logstr(0, "OK");
				else
					logstrf(0, "%s: illegal parameter", argv[0]);
				break;
			}
		}

		if(!cmd->cmd)
			logstrf(0, "%s: Command not found", argv[0]);
	}

	// free arg
	for(; --argc >= 0; )
		free(argv[argc]);
	free(argv);

	return;
}

int checkXevents(void)
{
	XEvent ev;
	while(XCheckMaskEvent(X.disp, 0xFFFFFFFF, &ev))
	{
		//printf("%d\n", ev.type);
		switch(ev.type)
		{
			/*
			case Expose:
				XDrawImageString(X.disp, X.wnd, X.gc, 20, 50, "Hi!", 3);
				XFillArc(X.disp, X.wnd, X.gc, 50, 70, 20, 20, 0, 360*64);

				break;
			*/
			case KeyPress:
				{

					switch(XLookupKeysym((XKeyEvent*)&ev, 0))
					{
					case XK_Return:
						if(gstat.cmdmode)
						{
							gstat.cmdmode = FALSE;
							parseCmd(gstat.cmdstr);
						}else
						{
							if(cnode)
							{
								if(!cnode->tracerouted)
									traceAdd(cnode);
								else
								if(!cnode->resolved)
									resolveAdd(cnode);
							}
						}
						break;
					case XK_Left:
						if(gconf.threed && ((*(XKeyEvent*)&ev).state & ControlMask))
						{
							gconf.eye.x--;
						}else
						{
							if(!cnode)
								setCurNode(&nroot);
							else
							{
								struct tagNode *n;

								for(n = cnode->next; n; n = n->next)
								{
									if(isShowableNode(n))
										break;
								}
								if(n)
									setCurNode(n);
								else
								{
									if(cnode->parent)
									{
										//setCurNode(cnode->parent->child);
										for(n = cnode->parent->child; n; n = n->next)
										{
											if(isShowableNode(n))
												break;
										}
										if(n)
											setCurNode(n);
									}
								}
							}
						}
						break;
					case XK_Right:
						if(gconf.threed && ((*(XKeyEvent*)&ev).state & ControlMask))
						{
							gconf.eye.x++;
						}else
						{
							if(!cnode)
								setCurNode(&nroot);
							else
							{
								if(cnode->parent)
								{
#if 0
									struct tagNode **ppn;

									for(ppn = &cnode->parent->child; *ppn; ppn = &(*ppn)->next)
									{
										if((*ppn)->next == cnode)
											break;
									}
									if(!*ppn)
										for(ppn = &cnode->parent->child; (*ppn)->next; ppn = &(*ppn)->next)	// find last
											/*NULL*/;

									setCurNode(*ppn);
#endif
									struct tagNode *n, *pn;

									for(pn = NULL, n = cnode->parent->child; n; n = n->next)
									{
										if(isShowableNode(n))
											pn = n;
										if(n->next == cnode)
										{
											n = pn;
											break;
										}
									}
									if(!n)
									{
										for(pn = NULL, n = cnode->parent->child; n; n = n->next)
										{
											if(isShowableNode(n))
												pn = n;
										}
										n = pn;
									}

									if(n)
										setCurNode(n);
								}
							}
						}
						break;
					case XK_Up:
						if(gconf.threed && ((*(XKeyEvent*)&ev).state & ControlMask))
						{
							if((*(XKeyEvent*)&ev).state & ShiftMask)
								gconf.eye.z--;
							else
								gconf.eye.y--;
						}else
						{
							if(!cnode)
								setCurNode(&nroot);
							else
							{
								if(cnode->parent)
									setCurNode(cnode->parent);
							}
						}
						break;
					case XK_Down:
						if(gconf.threed && ((*(XKeyEvent*)&ev).state & ControlMask))
						{
							if((*(XKeyEvent*)&ev).state & ShiftMask)
								gconf.eye.z++;
							else
								gconf.eye.y++;
						}else
						{
							if(!cnode)
								setCurNode(&nroot);
							else
							{
								if(cnode->child)
								{
									struct tagNode *node;

									for(node = cnode->child; node; node = node->next)
										if(isShowableNode(node))
											break;

									if(node)
										setCurNode(node);
								}
							}
						}
						break;
					case XK_Escape:
						setCurNode(NULL);
						gstat.loadcnt = gstat.savecnt = gstat.nukecnt = 0;
						gstat.cmdmode = FALSE;
						break;
					case XK_F9:
						gstat.loadcnt = gstat.savecnt = 0;
						gstat.nukecnt++;
						if(gstat.nukecnt >= 5)
						{
							gstat.nukecnt = 0;
							freeAll();
						}
						break;
					case XK_F11:
						gstat.nukecnt = gstat.savecnt = 0;
						gstat.loadcnt++;
						if(gstat.loadcnt >= 3)
						{
							gstat.loadcnt = 0;
							doLoad(NULL, TRUE, FALSE);
						}
						break;
					case XK_F12:
						gstat.nukecnt = gstat.loadcnt = 0;
						gstat.savecnt++;
						if(gstat.savecnt >= 3)
						{
							gstat.savecnt = 0;
							doSave(NULL);
						}
						break;
					case XK_BackSpace:
						if(gstat.cmdmode)
						{
							int l = strlen(gstat.cmdstr);

							if(l > 0)
								gstat.cmdstr[l - 1] = '\0';
							else
								gstat.cmdmode = FALSE;
						}
						break;
					default:
						{
							KeySym key;
							char str[10];
							//char buf[32];

							XLookupString((XKeyEvent*)&ev, str, sizeof(str), &key, NULL);
							//sprintf(buf, "KeyPress %s", str);
							//XDrawImageString(X.disp, X.wnd, X.gc, 20, 40, buf, strlen(buf));

							if(!gstat.cmdmode)
							{
								if(str[0] == 'i')
									gconf.showinfo = !gconf.showinfo;
								if(str[0] == 'b')
									gconf.showbytes = !gconf.showbytes;
								if(str[0] == 'c')
									gconf.clipping = !gconf.clipping;
								if(str[0] == ':')
								{
									gstat.cmdstr[0] = '\0';
									gstat.cmdmode = TRUE;
								}
							}else
							{
								int l = strlen(gstat.cmdstr);

								if(l < 250)
								{
									gstat.cmdstr[l] = str[0];
									gstat.cmdstr[l + 1] = '\0';
								}
							}
						}
						break;
					}

				}
				break;
			/*
			case KeyRelease:
				{
					KeySym key;
					char str[10];
					char buf[32];

					XLookupString((XKeyEvent*)&ev, str, sizeof(str), &key, NULL);
					sprintf(buf, "KeyRelease %s", str);
					XDrawImageString(X.disp, X.wnd, X.gc, 20, 40, buf, strlen(buf));
				}
				break;
			*/
			//case UnmapNotify:
			//case DestroyNotify:
			//	return 1;
			case ButtonPress:
				{
					double x, y;
					x = ev.xbutton.x;
					y = ev.xbutton.y;
					if(gconf.threed)
					{
						if(!(ev.xbutton.state & ShiftMask))
						{
							M3 r;
							memcpy(gstat.saveTransM44, gstat.transM44, sizeof(double)*16);
							if(!getHitFloorM3(&r, x, y))
								break;
							x = r.x + X.ww / 2;
							y = r.z + X.wh / 2;
						}
					}
					if(ev.xbutton.state & ControlMask)
					{
						switch(ev.xbutton.button)
						{
						case Button1:
						case Button2:
						case Button3:
							gstat.tdragging = TRUE;
							gstat.tdragged = FALSE;
							gstat.dragpx = x;
							gstat.dragpy = y;
							break;
							/*
							//gstat.tdragging = TRUE;
							//gstat.tdragged = FALSE;
							//gstat.dragpx = x;
							//gstat.dragpy = y;
							gconf.lookat.x = x - X.ww / 2;
							gconf.lookat.y = 0;
							gconf.lookat.z = y - X.wh / 2;
							break;
							*/
						}
					}else
					{
						switch(ev.xbutton.button)
						{
						case Button3:
							{
								struct tagNode *hit;

								gstat.cdragging = TRUE;
								if(!cnode && ((hit = getHitNode(x - X.ww / 2, y - X.wh / 2)) == NULL))
								{
									gstat.dragpd = atan2(y - X.wh / 2 - nroot.y, x - X.ww / 2 - nroot.x) / 2 / M_PI;
								}else
								{
									if(!cnode)
										setCurNode(hit);
									gstat.dragpx = x;
									gstat.dragpy = y;
								}
							}
							break;
						case Button1:
							setCurNode(getHitNode(x - X.ww / 2, y - X.wh / 2));
							break;
						case Button2:
							gconf.runode = distance(nroot.x, nroot.y, x - X.ww / 2, y - X.wh / 2);
							break;
						case Button4:
							logstr(0, "Button4");
							break;
						case Button5:
							logstr(0, "Button5");
							break;
						}
					}
				}
				break;
			case MotionNotify:
				{
					double x, y;
					x = ev.xmotion.x;
					y = ev.xmotion.y;
					if(gconf.threed)
					{
						if(!(ev.xmotion.state & ShiftMask))
						{
							M3 r;
							int hit;
							memcpy(gstat.prevTransM44, gstat.transM44, sizeof(double)*16);
							memcpy(gstat.transM44, gstat.saveTransM44, sizeof(double)*16);
							hit = getHitFloorM3(&r, x, y);
							memcpy(gstat.transM44, gstat.prevTransM44, sizeof(double)*16);
							if(!hit)
								break;
							x = r.x + X.ww / 2;
							y = r.z + X.wh / 2;
						}
					}
					if(gstat.cdragging)
					{
						if((ev.xmotion.state & Button3Mask))
						{
							if(cnode)
							{
								int dx, dy;
								dx = x - gstat.dragpx;
								dy = y - gstat.dragpy;
								cnode->x			+= dx;
								cnode->posinfo.x	+= dx;
								cnode->posinfo.px	+= dx;
								cnode->y			+= dy;
								cnode->posinfo.y	+= dy;
								cnode->posinfo.py	+= dy;
								/*
								   if(cnode == &nroot)
								   setRootPos(cnode->x, cnode->y);
								 */

								gstat.dragpx = x;
								gstat.dragpy = y;
							}else
							{
								double d = atan2(y - X.wh / 2 - nroot.y, x - X.ww / 2 - nroot.x) / 2 / M_PI;

								gconf.rotate += d - gstat.dragpd;

								gstat.dragpd = d;
							}
						}
					}
					if(gstat.tdragging)
					{
						double dx, dy;
						gstat.tdragged = TRUE;
						dx = x - gstat.dragpx;
						dy = y - gstat.dragpy;
						if(ev.xmotion.state & ShiftMask)
						{
							if((ev.xmotion.state & Button1Mask) || (ev.xmotion.state & Button2Mask))
								gconf.eye.y += dy;
							if((ev.xmotion.state & Button1Mask) || (ev.xmotion.state & Button3Mask))
								gconf.lookat.y += dy;
						}else
						{
							if((ev.xmotion.state & Button1Mask) || (ev.xmotion.state & Button2Mask))
							{
								gconf.eye.x -= dx;
								gconf.eye.z -= dy;
							}
							if((ev.xmotion.state & Button1Mask) || (ev.xmotion.state & Button3Mask))
							{
								gconf.lookat.x -= dx;
								gconf.lookat.z -= dy;
							}
						}
						gstat.dragpx = x;
						gstat.dragpy = y;
						/*
						   if((ev.xmotion.state & Button3Mask))
						   {
								//int dx, dy;
								//dx = x - gstat.dragpx;
								//dy = y - gstat.dragpy;
								gconf.lookat.x = x;
								gconf.lookat.z = y;
								gstat.dragpx = x;
								gstat.dragpy = y;
							}
						 */
					}
				}
				break;
			case ButtonRelease:
				if(gstat.cdragging)
				{
					switch(ev.xbutton.button)
					{
					case Button3:
						gstat.cdragging = FALSE;
						break;
					}
				}
				if(gstat.tdragging)
				{
					gstat.tdragging = FALSE;
					if(!gstat.tdragged && (ev.xbutton.button == Button1 || ev.xbutton.button == Button2))
					{
						M3 m = {0, 0, 0};

						if(ev.xbutton.button == Button1)
						{
							m.x = gconf.eye.x - gconf.lookat.x;
							m.z = gconf.eye.z - gconf.lookat.z;
						}

						gconf.eye.x = gstat.dragpx - X.ww / 2 - m.x;
						//gconf->eye.y = 0;
						gconf.eye.z = gstat.dragpy - X.wh / 2 - m.z;
					}
					if(!gstat.tdragged && (ev.xbutton.button == Button1 || ev.xbutton.button == Button3))
					{
						gconf.lookat.x = gstat.dragpx - X.ww / 2;
						gconf.lookat.y = 0;
						gconf.lookat.z = gstat.dragpy - X.wh / 2;
					}
				}
				break;
			case ConfigureNotify:
				//puts("conf");

				if(X.ww != ev.xconfigure.width || X.wh != ev.xconfigure.height)
				{
					X.ww = ev.xconfigure.width;
					X.wh = ev.xconfigure.height;

					// root position is fixed!
					//setRootPos(X.ww / 2, X.wh / 2);
					setRootPos(0, 0);

					XFreePixmap(X.disp, X.pm);
					X.pm = XCreatePixmap(X.disp, X.wnd, X.ww, X.wh, DefaultDepth(X.disp, 0));
				}
				break;
		}
	}

	return 0;
}

void mulM44M4(double s[4][4], double a[4])
{
	double r[4];
	int i;

	for(i = 0; i < 4; i++)
		r[i] = s[i][0]*a[0] + s[i][1]*a[1] + s[i][2]*a[2] + s[i][3]*a[3];

	for(i = 0; i < 4; i++)
		a[i] = r[i];

	return;
}
void calc3D(double p[4], double transM44[4][4])
{
	p[3] = 1;

	mulM44M4(transM44, p);

	// Perspective
	p[0] /= p[3];
	p[1] /= p[3];
	p[2] /= p[3];

	// ZoomToWindow
	p[0] =  p[0] * X.ww/2 + X.ww/2;
	p[1] = -p[1] * X.wh/2 + X.wh/2;

	gstat.curpointspersec++;
	gstat.curpointsperframe++;
}
void DebugXprintf(int x, int y, char *fmt, ...)	// TODO: this is debug routine.
{
	char ts[1024];
	va_list va;
	int lts;

	int dir, asc, desc;
	XCharStruct ova;

	va_start(va, fmt);
	lts = vsprintf(ts, fmt, va);
	va_end(va);

	XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);

	XDrawString(X.disp, X.pm, X.gc, x, y + ova.ascent, ts, lts);

	return;
}
void drawLine(double x1, double y1, double x2, double y2)
{
	if(gconf.clipping)
	{
		int c;
		if((c = clipping(&x1, &y1, &x2, &y2, 20, 20, X.ww - 20, X.wh - 20)) == -1)
			return;
		if(c)
		{
			XDrawArc(X.disp, X.pm, X.gc, x1 - 2, y1 - 2, 5, 5, 0, 360*64);
			XDrawArc(X.disp, X.pm, X.gc, x2 - 2, y2 - 2, 5, 5, 0, 360*64);
		}
	}
	XDrawLine(X.disp, X.pm, X.gc, x1, y1, x2, y2);
}
//#define	drawLine(x1,y1,x2,y2) XDrawLine(X.disp, X.pm, X.gc, x1, y1, x2, y2)
void draw3DCircleSub(GC gc, double x, double y, double r, int isfill, struct tagBound *b)
{
	double p[4], pp[2], center[4];
	int i;
	const int npoly = 12;

	if(isfill)
	{
		center[0] = x;
		center[1] = 0;
		center[2] = y;
		calc3D(center, gstat.transM44);
	}

	for(i = 0; i <= npoly; i++)
	{
		p[0] = cos((double)(i%npoly) / npoly * 2 * M_PI) * r + x;
		p[1] = 0;
		p[2] = sin((double)(i%npoly) / npoly * 2 * M_PI) * r + y;
		calc3D(p, gstat.transM44);
		if(i > 0)
		{
			if(0 < p[2] && p[2] < 1)
			{
				drawLine(pp[0], pp[1], p[0], p[1]);
				if(isfill)
				{
					XPoint po[3];
					po[0].x = center[0];
					po[0].y = center[1];
					po[1].x = pp[0];
					po[1].y = pp[1];
					po[2].x = p[0];
					po[2].y = p[1];
					XFillPolygon(X.disp, X.pm, gc, po, 3, Complex, CoordModeOrigin);
				}
				if(b)
				{
					if(p[0] < b->left)		b->left = p[0];
					if(b->right < p[0])		b->right = p[0];
					if(p[1] < b->top)		b->top = p[1];
					if(b->bottom < p[1])	b->bottom = p[1];
				}
			}
		}else
		{
			if(b)
			{
				b->left = b->right = p[0];
				b->top = b->bottom = p[1];
			}
		}

		pp[0] = p[0];
		pp[1] = p[1];
	}

//	if(b)
//		XDrawRectangle(X.disp, X.pm, X.gc, b->left, b->top, b->right - b->left, b->bottom - b->top);
}
void draw3DCircle(GC gc, double x, double y, double r, struct tagBound *b)
{
	draw3DCircleSub(gc, x, y, r, FALSE, b);
}
void fill3DCircle(GC gc, double x, double y, double r, struct tagBound *b)
{
	draw3DCircleSub(gc, x, y, r, TRUE, b);
}
void calcGlobe3D(double p[4], double x, double y, double r)
{
	double deg = y / 90;
	double z = -x / 180/2 + gGlobe.rot;

	double w;
	w = cos(deg * M_PI / 2) * r;
	p[1] = sin(deg * M_PI / 2) * r;

	p[0] = w * cos(z * M_PI * 2);
	p[2] = w * -sin(z * M_PI * 2);

	calc3D(p, gstat.transM44);

	return;
}
void doTraffic(struct tagNode *node, bool show)
{
	struct tagTraffic *traf, **pptraf;

	if(!node->parent || (gconf.globe && (node->cityindex < 0 || node->parent->cityindex < 0 || node->cityindex == node->parent->cityindex))) {
		show = FALSE;
	}

	for(traf = node->traffic, pptraf = &node->traffic; traf; )
	{
		double dpin = gconf.pktinterval;	// TODO: refer node->ping

		if(!(gconf.globe && node->cityindex == node->parent->cityindex) && gstat.ctime < traf->time + dpin)
		{	// draw
			if(gconf.viewTraffic && show)	// !gconf.viewTraffic don't only draw(, or add new traf).
			{
				double x, y, r;
				double rat;

				r = 2;
				if(traf->pktsize >= 10)
					r = 3;
				if(traf->pktsize >= 100)
					r = 4;
				if(traf->pktsize >= 1000)
					r = 5;

				rat = (gstat.ctime - traf->time) / dpin;
				if(traf->isuplink)
					rat = 1 - rat;

				if(rat < 0)
					rat = 0;

				if(gconf.globe)
				{
					double sx = gGlobe.cities[node->parent->cityindex].x, sy = gGlobe.cities[node->parent->cityindex].y;
					double dx = gGlobe.cities[node->cityindex].x, dy = gGlobe.cities[node->cityindex].y;
					double xx, yy;
					double p[4];

					if(distance(sx, sy, dx, dy) > distance(sx, sy, dx + 360, dy))
						dx += 360;
					if(distance(sx, sy, dx, dy) > distance(sx, sy, dx - 360, dy))
						dx -= 360;

					xx = sx + (dx - sx) * rat;
					yy = sy + (dy - sy) * rat;

					calcGlobe3D(p, xx, yy, gconf.globerad + sin(rat * M_PI) * gconf.globelineheight);
					x = p[0];
					y = p[1];
				}else
				{
					double deg, dis;

					deg = atan2(node->parent->y - node->y, node->parent->x - node->x);
					dis = distance(node->x, node->y, node->parent->x, node->parent->y) * rat;

					x = node->x + cos(deg) * dis;
					y = node->y + sin(deg) * dis;
					if(!gconf.threed)
					{
						x += X.ww / 2;
						y += X.wh / 2;
					}else
					{
						double p[4];

						p[0] = x;
						p[1] = 0;
						p[2] = y;

						calc3D(p, gstat.transM44);

						x = p[0];
						y = p[1];
					}
				}

				switch(traf->proto)
				{
				case IPPROTO_TCP:
					XSetForeground(X.disp, X.gc, gconf.protocolor.tcpPx);
					break;
				case IPPROTO_UDP:
					XSetForeground(X.disp, X.gc, gconf.protocolor.udpPx);
					break;
				case IPPROTO_ICMP:
					XSetForeground(X.disp, X.gc, gconf.protocolor.icmpPx);
					break;
				default:
					XSetForeground(X.disp, X.gc, gconf.colorPx);
					break;
				}
				XFillArc(X.disp, X.pm, X.gc, x - r, y - r, r*2, r*2, 0, 360*64);
				XSetForeground(X.disp, X.gc, gconf.colorPx);
				if(gconf.showpktsize)
				{
					char ts[256];
					int lts = sprintf(ts, "%zd", traf->pktsize);
					XDrawString(X.disp, X.pm, X.gc, x + r, y - 6, ts, lts);
				}
			}
		}else
		{	// route next
			// either reached or routed, cut out this traf from this node.
			*pptraf = traf->next;
			traf->time = gstat.ctime;

			if((traf->isuplink && node == traf->target/*if uplink*/) || (!traf->isuplink && node->parent == traf->target/*if downlink*/))
			{	// reached target
				free(traf);
			}else
			{
				if(!traf->isuplink && node->parent == &nroot)
				{	// incoming to root, U-turn!
					struct tagNode *nxnode;

					traf->isuplink = TRUE;

					if((nxnode = searchNodeByIP(traf->target->ip)) == NULL)
					{
						puts("traf-uturn: no child");
						//abort();
						free(traf);
						traf = NULL;
					}
					while(nxnode && nxnode->parent != &nroot)
					{
						nxnode = nxnode->parent;
					}
					if(!nxnode)
					{
						puts("traf-uturn: no parent");
						//abort();
						free(traf);
						traf = NULL;
					}

					if(traf)
					{
						traf->next = nxnode->traffic;
						nxnode->traffic = traf;
					}
				}else
				{
					struct tagNode *nxnode;

					if(traf->isuplink)
					{	// uplink: from root
						if((nxnode = searchNodeByIPFrom(traf->target->ip, node)) == NULL)
						{
							puts("traf-next: no child");
							//abort();
							free(traf);
							traf = NULL;
						}
						while(nxnode && nxnode->parent != node)
						{
							nxnode = nxnode->parent;
						}
						if(!nxnode)
						{
							puts("traf-next: no parent");
							//abort();
							free(traf);
							traf = NULL;
						}
					}else
					{	// downlink: to root
						nxnode = node->parent;
					}
					if(traf)
					{
						traf->next = nxnode->traffic;
						nxnode->traffic = traf;
					}
				}
			}

			traf = *pptraf;
			continue;
		}
		pptraf = &traf->next, traf = traf->next;
	}
}
void buildNetwork(struct tagNode *node, int ping, double astart, double aarea, int hops, struct tagNode *posparent, int draw)
{
	int /*i, */acc;	// ACCumurator
	char ts[64];
	int lts;

	int pleafs; // pleafs used only when node->parent, so not initializing is ok.

	if(node->parent)
	{
		struct tagNode *n;

		pleafs = node->parent->leafs;
		if(!node->parent->parent && gconf.bundle) // if i am a direct child of root, and bundle enabled...
		{
			for(n = node; n; n = n->next) // from me, iterate all siblings,
			{
				if(!isShowableNode(n)) // if it is not showable,
				{
					int l = n->leafs;

					if(l == 0) // if zero, i am the one.
						l = 1;

					pleafs -= l; // parent does not have these leaves... subtract.
				}
			}
		}
	}

	for(/*i = 0, */acc = 0; node; node = node->next/*, i++*/)
	{
		int r;

		// Node position calculation
		if(node->parent)	// if Not root
		{
			double deg;
			int x, y;
			int p = node->ping;
			int l = node->leafs;

			if(!node->tracerouted || (node->tracerouted && node->pingfail))
				p = gconf.runode;

			if(p < gconf.minping)
				p = gconf.minping;
			if(p > gconf.maxping)
				p = gconf.maxping;

			if(l == 0) // if leaf node
				l = 1;

			deg = astart + (acc + l/2.0) / pleafs * aarea; // l/2.0: center. acc adv. by leafs, it effectively ranges by leafs in aarea.
			node->posinfo.deg = 1 - deg + 0.25; // this is for autorotate in relative, but expr is from absolute...??
			switch(gconf.posmode)
			{
			case 0: // absolute
				if(node != cnode || !gstat.cdragging)
				{
					node->posinfo.px = cos((1 - deg + 0.25) * 2 * M_PI) * (ping + p) + nroot.x;
					node->posinfo.py = sin((1 - deg + 0.25) * 2 * M_PI) * (ping + p) + nroot.y;
				}
				deg += gconf.rotate;
				x = cos(deg * 2 * M_PI) * (ping + p) + nroot.x;
				y = sin(deg * 2 * M_PI) * (ping + p) + nroot.y;
				if(node != cnode || !gstat.cdragging)
				{
					node->posinfo.x = x;
					node->posinfo.y = y;
				}
				break;
			case 1: // relative
				if(node != cnode || !gstat.cdragging)
				{
					node->posinfo.px = cos((1 - deg + 0.25) * 2 * M_PI) * (p) + node->parent->posinfo.x;
					node->posinfo.py = sin((1 - deg + 0.25) * 2 * M_PI) * (p) + node->parent->posinfo.y;
				}
				deg += gconf.rotate;
				x = cos(deg * 2 * M_PI) * (p) + node->parent->posinfo.x;
				y = sin(deg * 2 * M_PI) * (p) + node->parent->posinfo.y;
				if(node != cnode || !gstat.cdragging)
				{
					node->posinfo.x = x;
					node->posinfo.y = y;
				}
				break;
			}

			if(node != cnode || !gstat.cdragging) {
				if(!gconf.maxhop || hops <= gconf.maxhop + 1) {
					if(gconf.movemode == -1) {
						int mc;
						int nx, ny;

						for(mc = hops; mc > 0; mc--)
						{
							nx = ((node->x)*(mc - 1) + x) / mc;
							ny = ((node->y)*(mc - 1) + y) / mc;

							//	if(node->x != nx || node->y != ny)
							break;
						}
						node->x = nx;
						node->y = ny;
					} else {
						if(gconf.movemode == 0) {
							node->x = x;
							node->y = y;
						}else{
							if(gconf.movemode > 0) {
								node->x = ((node->x)*(gconf.movemode - 1) + x) / gconf.movemode;
								node->y = ((node->y)*(gconf.movemode - 1) + y) / gconf.movemode;
							}
						}
					}
				} else {
					// nonsense for now, but have mean for prepare to not-limit and "expanding animation" from parent.
					node->x = posparent->x;
					node->y = posparent->y;
				}
			}
		}

		// Node and traffics drawing
		if(draw && ((!gconf.maxhop || hops <= gconf.maxhop + 1) && isShowableNode(node)))
		{
			struct tagBound cbound;
			int nx, ny;
			int show = TRUE;

			// position adjusting
			nx = node->x;
			ny = node->y;
			//ny = pow((double)ny / (X.wh/4.0), 2) * X.wh/4.0 + X.wh/4.0;
			//ny = 1 / (-ny / (X.wh / 4.0)) * X.wh * 4.0;
			if(!gconf.threed)
			{
				nx += X.ww / 2;
				ny += X.wh / 2;
			}else
			{
				double p[4];

				p[0] = nx;
				p[1] = 0;
				p[2] = ny;

				calc3D(p, gstat.transM44);

				nx = p[0];
				ny = p[1];

				if(p[2] < 0 || 1 < p[2])
					show = FALSE;
			}

			// set line style
			XSetLineAttributes(X.disp, X.gc, 1, node->pingfail ? LineDoubleDash : LineSolid, CapButt, JoinMiter);

			// Draw line from me to parent
			if(node->parent)	// if NOT root
			{
				int pnx, pny;

				pnx = node->parent->x;
				pny = node->parent->y;
				//pny = pow((double)pny / (X.wh/4.0), 2) * X.wh/4.0 + X.wh/4.0;
				//pny = 1 / (-pny / (X.wh / 4.0)) * X.wh * 4.0;
				if(!gconf.threed)
				{
					pnx += X.ww / 2;
					pny += X.wh / 2;
				}else
				{
					double p[4];

					p[0] = pnx;
					p[1] = 0;
					p[2] = pny;

					calc3D(p, gstat.transM44);

					pnx = p[0];
					pny = p[1];

					if(p[2] < 0 || 1 < p[2])
						show = FALSE;
				}

				if(show)
					drawLine(pnx, pny, nx, ny);
			}

			// draw traffic: don't if(gstat.viewTraffic) here, this routine includes moving traffic!
			doTraffic(node, show);

			// adjust radius
			r = gconf.nodeRadius;
			if(!node->parent)	// if root
				r = gconf.rootRadius;

			//r = r * (1.0 / (ny / X.wh));
			//printf("%d\n", ny);

			// draw node
			if(show)
			{
				if(gconf.threed)
				{
					if(node == cnode || node->marked)
						fill3DCircle((node != cnode && node->marked) ? X.gcStripe : X.gc, node->x, node->y, r, &cbound);
					else
						draw3DCircle(X.gc, node->x, node->y, r, &cbound);

					if(node->tracerouted && !node->pingfail)
						draw3DCircle(X.gc, node->x, node->y, r + 1, NULL);
				}else
				{
					cbound.left = nx - r;
					cbound.top = ny - r;
					cbound.right = nx + r;
					cbound.bottom = ny + r;
					if(node != cnode && !node->marked)
						XDrawArc(X.disp, X.pm, X.gc, nx - r, ny - r, r*2, r*2, 0, 360*64);
					else
					{
						if(node != cnode && node->marked)
							XFillArc(X.disp, X.pm, X.gcStripe, nx - r, ny - r, r*2, r*2, 0, 360*64);
						else
							XFillArc(X.disp, X.pm, X.gc, nx - r, ny - r, r*2, r*2, 0, 360*64);
					}
				}
			}

			// draw recent-added mark
			if(show && node->tradd + 2 > gstat.ctime)
			{
				double t = (2 - (gstat.ctime - node->tradd)) / 2;
				int rr = r + t * 30;

				XDrawArc(X.disp, X.pm, X.gc, nx - rr, ny - rr, rr*2, rr*2, 0, 360*64 * t);
			}

			// draw packet dump
			if(show && gconf.viewPacket)
			{
				int j;

				for(j = 0; j < 3; j++)
					if(node->packet[j])
						break;

				if(j < 3)
				{
					int ox;

					if(nroot.x < node->x)
					{
						ox = 20;
						drawLine(nx, ny, nx + 20, ny - 20);
					}else
					{
						ox = -20 - 6*12;
						drawLine(nx, ny, nx - 20, ny - 20);
					}
					drawLine(nx + ox, ny - 20, nx + ox + 6*12, ny - 20);

					for(j = 0; j < 3; j++)
					{
						if(node->packet[j])
						{
							int l = strlen(node->packetptr[j]);

							if(l > 12)
								l = 12;

							XDrawString(X.disp, X.pm, X.gc, nx + ox, ny - 20 - 2 - 12*j, node->packetptr[j], l);

							node->packetptr[j]++;

							if(!*node->packetptr[j])
							{
								free(node->packet[j]);
								node->packetptr[j] = NULL;
								node->packet[j] = NULL;
							}
						}
					}
				}
			}

			// draw node information
			if(show && (cnode == node || gconf.showinfo))
			{
				int dir, asc, desc;
				XCharStruct ova;

				lts = sprintf(ts, IPFMT, IPARG(node->ip));
				XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
				XDrawString(X.disp, X.pm, X.gc, nx - ova.width/2, cbound.bottom + 12, ts, lts);

				if(node->name)
				{
					int ln = strlen(node->name);

					XQueryTextExtents(X.disp, X.font, node->name, ln, &dir, &asc, &desc, &ova);
					XDrawString(X.disp, X.pm, X.gc, nx - ova.width/2, cbound.bottom + 12 + 10, node->name, ln);
				}

				if(!gconf.showbytes)
					lts = sprintf(ts, "%d,%d", node->childs, node->leafs);
				else
					lts = sprintf(ts, "%" PRIu64, node->downbyte);
				XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
				XDrawString(X.disp, X.pm, X.gc, nx - ova.width/2, cbound.top - 2, ts, lts);

				if(!gconf.showbytes)
					lts = sprintf(ts, "%d #%d", node->ping, hops - 1);
				else
					lts = sprintf(ts, "%" PRIu64, node->upbyte);
				XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
				XDrawString(X.disp, X.pm, X.gc, nx - ova.width/2, cbound.top - 2 - 10, ts, lts);
			}
		}

		// dive into child node
		//if(node->parent && !node->child)
		//	(*count)++;
		if(node->child && isShowableNode(node)/* && (!gconf.maxhop || hops <= gconf.maxhop)*/)
		{
			int p = node->ping;
			double as = 0.0, aa = 1.0;
			int l = node->leafs;

			if(!node->tracerouted)
				p = gconf.runode;

			if(p < gconf.minping)
				p = gconf.minping;
			if(p > gconf.maxping)
				p = gconf.maxping;

			if(node->parent)
			{
				as = (double)acc / pleafs;
				aa = (double)node->leafs / pleafs;
				l = pleafs;
			}

			buildNetwork(node->child/*, count*/, ping + p, astart + (double)acc/l * aarea, (double)node->leafs/l * aarea, hops + 1, (!gconf.maxhop || hops <= gconf.maxhop + 1) ? node : posparent, draw);
		}

		if(isShowableNode(node))
		{
			if(!node->child)
			{
				acc++; // TODO if !node->child, node->leafs==0?
			}else
				acc += node->leafs;
		}
	}

	return;
}

void calcTransformM44(double transM44[][4])
{
	setIdentM44(transM44);

	{
		double viewM44[4][4];
		getViewM44(viewM44, &gconf.lookat, &gconf.lookup, &gconf.eye);
		mulM44M44(transM44, viewM44);
	}
	{
		double persM44[4][4];
		getPersM44(persM44, gconf.fov, gconf.threedzn, gconf.threedzf, (double)X.ww / X.wh);
		mulM44M44(transM44, persM44);
	}
	transposeM44(transM44);
}
void initGlobe()
{
	FILE *fp;
	char ts[1024];
	char *pts;
	int lts;

	lts = sprintf(ts, "Loading cities.dat");
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	if(!(fp = fopen("data/cities.dat", "r")))
	{
		puts("ERROR: data/cities.dat not found");
		abort();
	}
	while(!feof(fp))
	{
		if(!fgets(ts, 1024, fp))
			break;
		for(pts = ts + strlen(ts) - 1; pts >= ts && (*pts == '\n' || *pts == '\r'); pts--)
			*pts = '\0';

		gGlobe.cities = remalloc(gGlobe.cities, sizeof(*gGlobe.cities) * (gGlobe.ccities + 1));

		gGlobe.cities[gGlobe.ccities].x = atof(strtok(ts, "\t"));
		gGlobe.cities[gGlobe.ccities].y = atof(strtok(NULL, "\t"));
		gGlobe.cities[gGlobe.ccities].popul = atol(strtok(NULL, "\t"));
		gGlobe.cities[gGlobe.ccities].ismetro = atoi(strtok(NULL, "\t"));
		gGlobe.cities[gGlobe.ccities].country = strdup(strtok(NULL, "\t"));
		gGlobe.cities[gGlobe.ccities].cityname = strdup(strtok(NULL, "\t"));

		gGlobe.ccities++;
	}
	fclose(fp);

	lts = sprintf(ts, "Loading coastlines.dat");
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	if(!(fp = fopen("data/coastlines.dat", "r")))
	{
		puts("ERROR: data/coastlines.dat not found");
		abort();
	}
	while(!feof(fp))
	{
		if(!fgets(ts, 1024, fp))
			break;

		for(pts = ts + strlen(ts) - 1; pts >= ts && (*pts == '\n' || *pts == '\r'); pts--)
			*pts = '\0';

		if(!strcmp(ts, "b"))
		{
			gGlobe.ccoasts++;
			gGlobe.coasts = remalloc(gGlobe.coasts, sizeof(*gGlobe.coasts) * (gGlobe.ccoasts + 1));
			gGlobe.coasts[gGlobe.ccoasts].cpoints = 0;
			gGlobe.coasts[gGlobe.ccoasts].pts = NULL;
		}else
		{
			int po = gGlobe.coasts[gGlobe.ccoasts].cpoints;
			gGlobe.coasts[gGlobe.ccoasts].pts = remalloc(gGlobe.coasts[gGlobe.ccoasts].pts, sizeof(*gGlobe.coasts->pts) * (po + 1));
			gGlobe.coasts[gGlobe.ccoasts].pts[po].x = atof(strtok(ts, " "));
			gGlobe.coasts[gGlobe.ccoasts].pts[po].y = atof(strtok(NULL, " "));
			gGlobe.coasts[gGlobe.ccoasts].cpoints++;
		}
	}
	gGlobe.ccoasts++;
	fclose(fp);

	lts = sprintf(ts, "Loading international.dat");
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	if(!(fp = fopen("data/international.dat", "r")))
	{
		puts("ERROR: data/international.dat not found");
		abort();
	}
	while(!feof(fp))
	{
		if(!fgets(ts, 1024, fp))
			break;
		for(pts = ts + strlen(ts) - 1; pts >= ts && (*pts == '\n' || *pts == '\r'); pts--)
			*pts = '\0';

		if(!strcmp(ts, "b"))
		{
			gGlobe.cinterns++;
			gGlobe.interns = remalloc(gGlobe.interns, sizeof(*gGlobe.interns) * (gGlobe.cinterns + 1));
			gGlobe.interns[gGlobe.cinterns].cpoints = 0;
			gGlobe.interns[gGlobe.cinterns].pts = NULL;
		}else
		{
			int po = gGlobe.interns[gGlobe.cinterns].cpoints;
			gGlobe.interns[gGlobe.cinterns].pts = remalloc(gGlobe.interns[gGlobe.cinterns].pts, sizeof(*gGlobe.interns->pts) * (po + 1));
			gGlobe.interns[gGlobe.cinterns].pts[po].x = atof(strtok(ts, " "));
			gGlobe.interns[gGlobe.cinterns].pts[po].y = atof(strtok(NULL, " "));
			gGlobe.interns[gGlobe.cinterns].cpoints++;
		}
	}
	gGlobe.cinterns++;
	fclose(fp);

	lts = sprintf(ts, "Loading iplist.dat       ");
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	{
		int lc = 0;	// loadcounter

		if(!(fp = fopen("data/iplist.dat", "r")))
		{
			puts("ERROR: data/iplist.dat not found");
			abort();
		}
		while(!feof(fp))
		{
			if(!fgets(ts, 1024, fp)) {
				break;
			}

			for(pts = ts + strlen(ts) - 1; pts >= ts && (*pts == '\n' || *pts == '\r'); pts--) {
				*pts = '\0';
			}

			gGlobe.ips = remalloc(gGlobe.ips, sizeof(*gGlobe.ips) * (gGlobe.cips + 1));
			gGlobe.ips[gGlobe.cips].ip = parseIPString(strtok(ts, "\t"));
			gGlobe.ips[gGlobe.cips].mask = htonl(~(atol(strtok(NULL, "\t")) - 1));
			gGlobe.ips[gGlobe.cips].cid = -1;
			{
				int i;
				char *co = strtok(NULL, "\t");
				char tts[1024];

				lts = sprintf(tts, "Binding country... %c", loadchar[lc]);
				lc = (lc + 1) % 4;
				XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, tts, lts);

				if(co != NULL) { /* if not reserved (~= assigned) */
					for(i = 0; i < gGlobe.ccities; i++) {
						if(!strcmp(gGlobe.cities[i].country, co) && gGlobe.cities[i].ismetro)
						{
							gGlobe.ips[gGlobe.cips].cid = i;
							break;
						}
					}
				}

				//if(i == gGlobe.ccities)
				//	printf("Unable to bind %s\n", co);
			}
			gGlobe.cips++;
		}
		fclose(fp);
	}

	lts = sprintf(ts, "Adding private mask");
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	{
		struct{
			u_int32_t ip;
			u_int32_t mask;
		}sips[] = {
			{0x7F000000, 0x00FFFFFF},
			{0x0A000000, 0x00FFFFFF},
			{0xAC100000, 0x000FFFFF},
			{0xC0A80000, 0x0000FFFF},
		};
		{
			int i, j;

			for(i = 0; i < gGlobe.ccities; i++)
				if(!strcmp(gGlobe.cities[i].country, "Japan") && gGlobe.cities[i].ismetro)
				{
					for(j = 0; j < sizeof(sips) / sizeof(sips[0]); j++)
					{
						gGlobe.ips = remalloc(gGlobe.ips, sizeof(*gGlobe.ips) * (gGlobe.cips + 1));
						gGlobe.ips[gGlobe.cips].ip = htonl(sips[j].ip);
						gGlobe.ips[gGlobe.cips].mask = htonl(~sips[j].mask);
						gGlobe.ips[gGlobe.cips].cid = i;
						gGlobe.cips++;
					}
					break;
				}
		}
	}

	return;
}
int globeFindCountry(u_int32_t ip)
{
	int i;
	char ts[256];
	int lts;

	lts = sprintf(ts, "Finding country of "IPFMT, IPARG(ip));
	XDrawImageString(X.disp, X.wnd, X.gc, 5, X.wh - 5, ts, lts);

	for(i = 0; i < gGlobe.cips; i++)
	{
		if((ip & gGlobe.ips[i].mask) == gGlobe.ips[i].ip)
		{
			//printf(IPFMT" as %d\n", IPARG(ip), gGlobe.ips[i].cid);
			return gGlobe.ips[i].cid;
		}
	}
	//printf(IPFMT" unknown\n", IPARG(ip));

	return -1;
}
void doGlobeNodes(struct tagNode *node)
{
	for(; node; node = node->next)
	{
		int i;

		if(node->cityindex == -1)
		{
			if((i = globeFindCountry(node->ip)) > -1)
				node->cityindex = i;
			else
				node->cityindex = -2;
		}
		if(node->cityindex > -1)
		{
			int i = node->cityindex;
			double p[4];

			if(gconf.globeip)
			{
				calcGlobe3D(p, gGlobe.cities[i].x, gGlobe.cities[i].y, gconf.globerad);
				DebugXprintf(p[0], p[1], IPFMT, IPARG(node->ip));
			}

			if(node->parent && node->parent->cityindex > -1 && node->cityindex != node->parent->cityindex)
			{
				int j = node->parent->cityindex;
				double pp[2];
				double k;
				double sx = gGlobe.cities[j].x, sy = gGlobe.cities[j].y;
				double dx = gGlobe.cities[i].x, dy = gGlobe.cities[i].y;

				//XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);
				if(distance(sx, sy, dx, dy) > distance(sx, sy, dx + 360, dy))
				{
					//XSetLineAttributes(X.disp, X.gc, 2, LineSolid, CapButt, JoinMiter);
					dx += 360;
				}
				if(distance(sx, sy, dx, dy) > distance(sx, sy, dx - 360, dy))
				{
					//XSetLineAttributes(X.disp, X.gc, 2, LineSolid, CapButt, JoinMiter);
					dx -= 360;
				}

				for(k = 0; k <= 1.0; k += 1.0 / gconf.globelinediv)
				{
					double x = sx + (dx - sx) * k;
					double y = sy + (dy - sy) * k;

					calcGlobe3D(p, x, y, gconf.globerad + sin(k * M_PI) * gconf.globelineheight);

					if(k > 0)
					{
						double ntus = get_time();

						ntus = ntus - (int)ntus;

						if(gconf.globehilight && (k <= ntus && ntus <= (k + 1.0/gconf.globelinediv)))
							XSetForeground(X.disp, X.gc, gconf.globehlcolorPx);
						drawLine(pp[0], pp[1], p[0], p[1]);
						if(gconf.globehilight && (k <= ntus && ntus <= (k + 1.0/gconf.globelinediv)))
							XSetForeground(X.disp, X.gc, gconf.colorPx);
					}

					pp[0] = p[0];
					pp[1] = p[1];
				}

			}

			doTraffic(node, TRUE);
		}

		if(node->child)
			doGlobeNodes(node->child);
	}

	return;
}
void doGlobe()
{
	if(!gGlobe.cities)
		initGlobe();

	XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);
	XSetForeground(X.disp, X.gc, gconf.globegridcolorPx);
	{
		double r = gconf.globerad;
		double p[4], pp[4];
		{
			double z;
			int i, ndiv = 32;

			// horiz grid
			for(z = -1; z < 1; z += 1.0 / 9)
			{
				for(i = 0; i <= ndiv; i++)
				{
					double deg = (double)i / ndiv + gGlobe.rot;
					double x;//m[4][4];
					p[0] =x= cos(z * M_PI / 2) * r;
					p[1] = sin(z * M_PI / 2) * r;
					p[2] = 0;

					/*
					   setIdentM44(m);
					   m[0][0] = cos(deg * M_PI * 2);
					   m[0][2] = -sin(deg * M_PI * 2);
					   m[2][0] = sin(deg * M_PI * 2);
					   m[2][2] = cos(deg * M_PI * 2);
					   mulM4M44(p, m);
					 */
					p[0] = x * cos(deg * M_PI*2);
					p[2] = x * -sin(deg * M_PI*2);

					calc3D(p, gstat.transM44);

					if(i > 0)
						drawLine(pp[0], pp[1], p[0], p[1]);
					pp[0] = p[0];
					pp[1] = p[1];
				}
			}

			// vert grid
			for(z = 0; z < 0.5; z += 1.0 / 18)
			{
				for(i = 0; i <= ndiv; i++)
				{
					double deg = (double)i / ndiv;
					double x;//m[4][4];
					p[0] =x= cos(deg * M_PI * 2) * r;
					p[1] = sin(deg * M_PI * 2) * r;
					p[2] = 0;

					/*
					   setIdentM44(m);
					   m[0][0] = cos(z * M_PI);
					   m[0][2] = -sin(z * M_PI);
					   m[2][0] = sin(z * M_PI);
					   m[2][2] = cos(z * M_PI);
					   mulM4M44(p, m);
					 */
					p[0] = x * cos((z + gGlobe.rot) * M_PI * 2);
					p[2] = x * -sin((z + gGlobe.rot) * M_PI * 2);

					calc3D(p, gstat.transM44);

					if(i > 0)
						drawLine(pp[2], pp[3], p[0], p[1]);
					pp[2] = p[0];
					pp[3] = p[1];
				}
			}
		}

		{
			int i, j;

			// international lines
			XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);
			XSetForeground(X.disp, X.gc, gconf.globeinterncolorPx);
			for(i = 0; i < gGlobe.cinterns; i++)
			{
				for(j = 0; j < gGlobe.interns[i].cpoints; j++)
				{
					calcGlobe3D(p, gGlobe.interns[i].pts[j].x, gGlobe.interns[i].pts[j].y, r);
					/*
					double deg = gGlobe.interns[i].pts[j].y / 90;
					double z = -gGlobe.interns[i].pts[j].x / 180/2 + gGlobe.rot;
					double x;
					x = cos(deg * M_PI / 2) * r;
					p[1] = sin(deg * M_PI / 2) * r;

					p[0] = x * cos(z * M_PI * 2);
					p[2] = x * -sin(z * M_PI * 2);

					calc3D(p, gstat.transM44);
					*/

					if(j > 0)
						drawLine(pp[0], pp[1], p[0], p[1]);
					pp[0] = p[0];
					pp[1] = p[1];
				}
			}

			// coastline
			XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);
			XSetForeground(X.disp, X.gc, gconf.colorPx);
			for(i = 0; i < gGlobe.ccoasts; i++)
			{
				for(j = 0; j < gGlobe.coasts[i].cpoints; j++)
				{
					calcGlobe3D(p, gGlobe.coasts[i].pts[j].x, gGlobe.coasts[i].pts[j].y, r);
					/*
					double deg = gGlobe.coasts[i].pts[j].y / 90;
					double z = -gGlobe.coasts[i].pts[j].x / 180/2 + gGlobe.rot;
					double x;
					x = cos(deg * M_PI / 2) * r;
					p[1] = sin(deg * M_PI / 2) * r;

					p[0] = x * cos(z * M_PI * 2);
					p[2] = x * -sin(z * M_PI * 2);

					calc3D(p, gstat.transM44);
					*/

					if(j > 0)
						drawLine(pp[0], pp[1], p[0], p[1]);
					pp[0] = p[0];
					pp[1] = p[1];
				}
			}

			// cities
			XSetForeground(X.disp, X.gc, gconf.globeinterncolorPx);
			XSetForeground(X.disp, X.gcStripe, gconf.colorPx);
			XSetFillStyle(X.disp, X.gcStripe, FillSolid);
			for(i = 0; i < gGlobe.ccities; i++)
			{
				calcGlobe3D(p, gGlobe.cities[i].x, gGlobe.cities[i].y, r);
				/*
				double deg = gGlobe.cities[i].y / 90;
				double z = -gGlobe.cities[i].x / 180/2 + gGlobe.rot;
				double x;
				x = cos(deg * M_PI / 2) * r;
				p[1] = sin(deg * M_PI / 2) * r;

				p[0] = x * cos(z * M_PI * 2);
				p[2] = x * -sin(z * M_PI * 2);

				calc3D(p, gstat.transM44);
				*/

				if(!gconf.globeshowonlymetro || gGlobe.cities[i].ismetro)
				{
					XPoint po[4];
					int r = (int)(log10(gGlobe.cities[i].popul) / 2);
					po[0].x = p[0];
					po[0].y = p[1] - r;
					po[1].x = p[0] + r;
					po[1].y = p[1];
					po[2].x = p[0];
					po[2].y = p[1] + r;
					po[3].x = p[0] - r;
					po[3].y = p[1];
					XFillPolygon(X.disp, X.pm, gGlobe.cities[i].ismetro ? X.gcStripe : X.gc, po, 4, Complex, CoordModeOrigin);
				}

				if(gGlobe.cities[i].ismetro)
				{
					//if(!strcmp(cities[i].country, "Japan")||!strcmp(cities[i].country, "Brazil"))
                    if(gconf.showinfo)
					{
						//XDrawArc(X.disp, X.pm, X.gc, p[0], p[1], 2, 2, 0, 360 * 64);
						XDrawString(X.disp, X.pm, X.gcStripe, p[0], p[1], gGlobe.cities[i].cityname, strlen(gGlobe.cities[i].cityname));
						XDrawString(X.disp, X.pm, X.gcStripe, p[0], p[1]+12, gGlobe.cities[i].country, strlen(gGlobe.cities[i].country));
					}
				}
			}

			XSetFillStyle(X.disp, X.gcStripe, FillOpaqueStippled);
			XSetForeground(X.disp, X.gc, gconf.colorPx);

			pthread_mutex_lock(&pmNodes);
			doGlobeNodes(&nroot);
			pthread_mutex_unlock(&pmNodes);
		}
	}

	gGlobe.rot += gconf.globerotdx;

	XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);
	XSetForeground(X.disp, X.gc, gconf.colorPx);

	return;
}
void doFrame(void)
{
	double fstart = get_time();

	// clear backbuffer
	XSetForeground(X.disp, X.gc, BlackPixel(X.disp, 0));
	XFillRectangle(X.disp, X.pm, X.gc, 0, 0, X.ww, X.wh);

	if(gstat.lasttime != (int)fstart)
	{
		gstat.lasttime = (int)fstart;
		gstat.fps = gstat.curframespersec;
		gstat.points = gstat.curpointspersec;
		gstat.curframespersec = 0;
		gstat.curpointspersec = 0;
	}
	gstat.curframespersec++;
	gstat.curpointsperframe = 0;

	XSetForeground(X.disp, X.gc, gconf.colorPx);
	if(cnode)
	{
		char ts[256], nts[256];

		if(cnode->name)
			sprintf(nts, " (%s)", cnode->name);
		else
			nts[0] = '\0';

		if(!cnode->tracerouted)
			sprintf(ts, "Press ENTER to traceroute "IPFMT"%s", IPARG(cnode->ip), nts);
		else
			sprintf(ts, "Node "IPFMT"%s was already tracerouted.", IPARG(cnode->ip), nts);
		XDrawString(X.disp, X.pm, X.gc, 5, 5 + 9, ts, strlen(ts));
	}
	if(gconf.threed)
		calcTransformM44(gstat.transM44);

	if(gconf.globe)
		doGlobe();

	/*
	{
		Window d1, d2;
		int x, y, d3, d4;
		unsigned int d5;
		M3 r;

		XQueryPointer(X.disp, X.wnd, &d1, &d2, &d3, &d4, &x, &y, &d5);

		if(getHitFloorM3(&r, x, y))
		{
			{
				double b[4] = {r.x - 1, r.y, r.z, 1};
				double c[4] = {r.x + 1, r.y, r.z, 1};
				calc3D(b, gstat.transM44);
				calc3D(c, gstat.transM44);
				XDrawLine(X.disp, X.pm, X.gc, b[0], b[1], c[0], c[1]);
			}
			{
				double b[4] = {r.x, r.y, r.z - 1, 1};
				double c[4] = {r.x, r.y, r.z + 1, 1};
				calc3D(b, gstat.transM44);
				calc3D(c, gstat.transM44);
				XDrawLine(X.disp, X.pm, X.gc, b[0], b[1], c[0], c[1]);
			}
			DebugXprintf(0, 20, "%f %f", r.x, r.z);
		}
	}
	*/
	if(!gconf.globe && gconf.threed && gconf.threedgrid.enabled)
	{
		double x, y;

		XSetLineAttributes(X.disp, X.gc, 1, LineSolid, CapButt, JoinMiter);

#define fourfive(n,m) ((int)(n)/m*m)
#define ffintv(n) fourfive(n,gconf.threedgrid.interval)
		for(y = ffintv(gconf.lookat.z) - gconf.threedgrid.interval*gconf.threedgrid.radius;
				y <= ffintv(gconf.lookat.z) + gconf.threedgrid.interval*gconf.threedgrid.radius;
				y += gconf.threedgrid.interval)
			for(x = ffintv(gconf.lookat.x) - gconf.threedgrid.interval*gconf.threedgrid.radius;
					x <= ffintv(gconf.lookat.x) + gconf.threedgrid.interval*gconf.threedgrid.radius;
					x += gconf.threedgrid.interval)
				if(SQR(x - gconf.lookat.x) + SQR(y - gconf.lookat.z) < SQR(gconf.threedgrid.interval*gconf.threedgrid.radius))
				{
					{
						double b[4] = {x - gconf.threedgrid.size, 0, y, 1};
						double c[4] = {x + gconf.threedgrid.size, 0, y, 1};
						calc3D(b, gstat.transM44);
						calc3D(c, gstat.transM44);
						if((0 < b[2] && b[2] < 1) && (0 < c[2] && c[2] < 1))
							drawLine(b[0], b[1], c[0], c[1]);
					}
					{
						double b[4] = {x, 0, y - gconf.threedgrid.size, 1};
						double c[4] = {x, 0, y + gconf.threedgrid.size, 1};
						calc3D(b, gstat.transM44);
						calc3D(c, gstat.transM44);
						if((0 < b[2] && b[2] < 1) && (0 < c[2] && c[2] < 1))
							drawLine(b[0], b[1], c[0], c[1]);
					}
				}
	}

	gstat.ctime = get_time();

	if(!gconf.globe)
	{

		pthread_mutex_lock(&pmNodes);
		buildNetwork(&nroot, 0, 0.0, 1.0, 1, &nroot, TRUE);
		pthread_mutex_unlock(&pmNodes);
	}

	if(gstat.model.cpoints && gstat.model.clines)
	{
		int i;

		for(i = 0; i < gstat.model.clines; i++)
		{
			double p[4], q[4];
			p[0] = gstat.model.points[gstat.model.lines[i][0]].x;
			p[1] = gstat.model.points[gstat.model.lines[i][0]].y;
			p[2] = gstat.model.points[gstat.model.lines[i][0]].z;
			calc3D(p, gstat.transM44);
			q[0] = gstat.model.points[gstat.model.lines[i][1]].x;
			q[1] = gstat.model.points[gstat.model.lines[i][1]].y;
			q[2] = gstat.model.points[gstat.model.lines[i][1]].z;
			calc3D(q, gstat.transM44);
			drawLine(p[0], p[1], q[0], q[1]);
		}
	}

	{
		int dir, asc, desc;
		XCharStruct ova;
		int lts;
		char ts[256];

		if(gstat.nukecnt)
		{
			lts = sprintf(ts, "Press F9 %d times to NUKE ALL!", 5 - gstat.nukecnt);
			XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
			XDrawString(X.disp, X.pm, X.gc, X.ww - ova.width - 5, 13, ts, lts);
		}
		if(gstat.loadcnt)
		{
			lts = sprintf(ts, "Press F11 %d times to load!", 3 - gstat.loadcnt);
			XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
			XDrawString(X.disp, X.pm, X.gc, X.ww - ova.width - 5, 13, ts, lts);
		}
		if(gstat.savecnt)
		{
			lts = sprintf(ts, "Press F12 %d times to save!", 3 - gstat.savecnt);
			XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
			XDrawString(X.disp, X.pm, X.gc, X.ww - ova.width - 5, 13, ts, lts);
		}
	}
	if(gconf.clock)
	{
		int dir, asc, desc;
		XCharStruct ova;
		int lts;
		char ts[256];
		double ti;

		//if(!gstat.isoffline)
		//	ti = get_time();
		//else
		ti = get_time_double(&gstat.packettv);

		switch(gconf.clock)
		{
		case 1:	lts = sprintf(ts, "%d fps %d points(%d points now) / %.6f", gstat.fps, gstat.points, gstat.curpointsperframe, ti);	break;
		case 2:	lts = sprintf(ts, "%d fps %d points(%d points now) / %s", gstat.fps, gstat.points, gstat.curpointsperframe, getTimeString(&gstat.packettv)); break;
		}
		XQueryTextExtents(X.disp, X.font, ts, lts, &dir, &asc, &desc, &ova);
		XDrawString(X.disp, X.pm, X.gc, X.ww - ova.width - 5, X.wh - 5, ts, lts);
	}
	{
		int i;

		if(gstat.cmdmode)
		{
			char ts[256];

			sprintf(ts, ":%s_", gstat.cmdstr);
			XDrawString(X.disp, X.pm, X.gc, 5, X.wh - 5, ts, strlen(ts));
		}

		pthread_mutex_lock(&logs[0].pmLog);
		if(logs[0].log)
			for(i = 0; i < logs[0].lines; i++)
			{
				if(logs[0].log[i])
					XDrawString(X.disp, X.pm, X.gc, 5, X.wh - 5 - 10*(i + 1), logs[0].log[i], strlen(logs[0].log[i]));
			}
		pthread_mutex_unlock(&logs[0].pmLog);

		if(gconf.packetLog)
		{
			pthread_mutex_lock(&logs[1].pmLog);
			if(logs[1].log)
				for(i = 0; i < logs[1].lines; i++)
				{
					if(logs[1].log[i])
						XDrawString(X.disp, X.pm, X.gc, X.ww - 6*(4+9+32) - 5, 23 + 10*(logs[1].lines - i), logs[1].log[i], strlen(logs[1].log[i]));
				}
			pthread_mutex_unlock(&logs[1].pmLog);
		}
	}
	//XSetForeground(X.disp, X.gc, WhitePixel(X.disp, 0));
	XCopyArea(X.disp, X.pm, X.wnd, X.gc, 0, 0, X.ww, X.wh, 0, 0);

	XFlush(X.disp);

	{
		double fintv = get_time() - fstart;
		double fwant = 1.0 / gconf.restfps;

		if(gconf.restfps && fintv < fwant)
			usleep((fwant - fintv) * 1000000);
	}

	return;
}

int Xinit(int argc, char **argv)
{
	if(!(X.disp = XOpenDisplay(NULL)))
	{
		puts("Can't open display!!");
		return 1;
	}

	// default width and height
	X.ww = 640;
	X.wh = 480;
	// preset.
	//setRootPos(X.ww / 2, X.wh / 2);
	setRootPos(0, 0);

	X.wnd = XCreateSimpleWindow(X.disp, DefaultRootWindow(X.disp), 0, 0, X.ww, X.wh, 0, 0, BlackPixel(X.disp, 0));

	{
		XSetWindowAttributes att;
		att.backing_store = WhenMapped;
		XChangeWindowAttributes(X.disp, X.wnd, CWBackingStore, &att);
	}

	XSetStandardProperties(X.disp, X.wnd, "ng: network graphicalizer", "ng", None, argv, argc, NULL);

	X.gc = XCreateGC(X.disp, X.wnd, 0, 0);
	XSetBackground(X.disp, X.gc, BlackPixel(X.disp, 0));

	X.gcStripe = XCreateGC(X.disp, X.wnd, 0, 0);
	{
		int i, w = 5;
		Pixmap wstripe = XCreatePixmap(X.disp, X.wnd, w*2, w*2, 1);
		GC gc = XCreateGC(X.disp, wstripe, 0, 0);

		XSetForeground(X.disp, gc, WhitePixel(X.disp, 0));
		XFillRectangle(X.disp, wstripe, gc, 0, 0, w*2, w*2);

		XSetForeground(X.disp, gc, BlackPixel(X.disp, 0));
		for(i = 0; i < w*2; i++)
		{
			int x = w - i, xx = w;
			if(x < 0)
			{
				XDrawLine(X.disp, wstripe, gc, w*2 + x, i, w*2, i);
				xx = w + x;
				x = 0;
			}
			XDrawLine(X.disp, wstripe, gc, x, i, x + xx - 1, i);
		}

		XFreeGC(X.disp, gc);

		XSetStipple(X.disp, X.gcStripe, wstripe);
		XSetFillStyle(X.disp, X.gcStripe, FillOpaqueStippled);
	}

	X.fontst = XLoadQueryFont(X.disp, FONT_NORMAL);
	X.font = X.fontst->fid;
	XSetFont(X.disp, X.gc, X.font);
	if((X.fontKremst = XLoadQueryFont(X.disp, FONT_GLOBE)) == NULL)
	{
		// fallback
		X.fontKremst = X.fontst;
	}
	X.fontKrem = X.fontKremst->fid;
	XSetFont(X.disp, X.gcStripe, X.fontKrem);

	X.pm = XCreatePixmap(X.disp, X.wnd, X.ww, X.wh, DefaultDepth(X.disp, 0));

	XSelectInput(X.disp, X.wnd, ExposureMask | KeyPressMask | KeyReleaseMask | ButtonPressMask | ButtonReleaseMask | StructureNotifyMask | ButtonMotionMask);

	XMapRaised(X.disp, X.wnd);

	return 0;
}

int pcapInit(char *pdev, char *filter, pcap_t **pd)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if(getuid() != 0 || !access(pdev, R_OK))
	{
		printf("(offline)");
		if((*pd = pcap_open_offline(pdev, errbuf)) == NULL)
		{
			printf("<Can't init pcap>");
			return 1;
		}
		gstat.isoffline = TRUE;
		nroot.ip = parseIPString("127.0.0.1");
		return 0;
	}else
	{
		// openlive(dev, snaplen, promisc, timeout, err)
		if((*pd = pcap_open_live(pdev, 1500, 0, 1000, errbuf)) == NULL)
		{
			printf("<Can't init pcap>");
			return 1;
		}
	}
	{
		bpf_u_int32 localnet, netmask;

		pcap_if_t *devs;

		pcap_findalldevs(&devs, errbuf);
		while(devs && strcmp(devs->name, pdev))
			devs = devs->next;
		if(devs)
		{
			struct pcap_addr *a;

			for(a = devs->addresses; a; a = a->next)
			{
				nroot.ip = ((struct sockaddr_in*)a->addr)->sin_addr.s_addr;
				nroot.name = devs->description;	// TODO: resolute name

				if(!a->netmask)
					continue;

				netmask = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
				localnet = nroot.ip & netmask;

				break;
			}
			if(!a)
			{
				puts("Can't find addr!");
				return 1;
			}
		}
		pcap_freealldevs(devs);

		/*if(pcap_lookupnet(pdev, &localnet, &netmask, errbuf) < 0)
		{
			puts("Can't get inteface info!");
			return 1;
		}*/

		logstrf(0, "PCAP: if:%s addr:"IPFMT" net:"IPFMT" mask:"IPFMT, pdev, IPARG(nroot.ip), IPARG(localnet), IPARG(netmask));

		if(filter)
		{
			struct bpf_program fcode;

			logstrf(0, "PCAP: filter:%s", filter);

			if(pcap_compile(*pd, &fcode, filter, 1, netmask) < 0)
			{
				puts("Can't compile!");
				return 1;
			}
			if(pcap_setfilter(*pd, &fcode) < 0)
			{
				puts("Can't set filter!");
				return 1;
			}
		}
	}

	// pcap_loop(pdev, -1, callback, NULL);	// Null means no data passed to callback

	pcap_setnonblock(*pd, 1, errbuf);

	return 0;
}

int main(int argc, char *argv[])
{
	pcap_t *pd;

	logstr(0, "NG: Network Graphicalizer starting up.");

	printf("Pcap ");
	fflush(stdout);

	{
		char *dev, *filt;

		if(argc < 2)
			dev = "eth0";
		else
			dev = argv[1];
		if(argc < 3)
			filt = NULL;
		else
		{
			int i, fl = 0, flp;

			filt = NULL;

			for(i = 2; i < argc; i++)
			{
				flp = strlen(argv[i]) + 1;
				filt = remalloc(filt, fl + flp + 1);
				strcpy(filt + fl, argv[i]);
				strcpy(filt + fl + flp - 1, " ");
				fl += flp;
			}
		}

		if(pcapInit(dev, filt,  &pd))
		{
			printf("initfail(Not root?),skipping ");
			nroot.ip = parseIPString("127.0.0.1");
			//return 1;
		}

		if(filt)
			free(filt);
	}

	printf("Xinit ");
	fflush(stdout);

	if(!XInitThreads())
	{
		puts("X Thread Initialize Failed");
		return 1;
	}
	if(Xinit(argc, argv))
		return 1;

	printf("RAWSocket ");
	fflush(stdout);

	if(icmp_init(AF_INET))
	{
		printf("initfail(Not root?),skipping ");
		//return 1;
	}

	printf("Go ahead...\n");

	// set configure
	gconf.colorName = strdup(gconf.colorName);	// convert rdata to heap.
	gconf.colorPx = GetColor(X.disp, gconf.colorName);
	gconf.protocolor.tcp = strdup(gconf.protocolor.tcp);	// convert rdata to heap.
	gconf.protocolor.tcpPx = GetColor(X.disp, gconf.protocolor.tcp);
	gconf.protocolor.udp = strdup(gconf.protocolor.udp);	// convert rdata to heap.
	gconf.protocolor.udpPx = GetColor(X.disp, gconf.protocolor.udp);
	gconf.protocolor.icmp = strdup(gconf.protocolor.icmp);	// convert rdata to heap.
	gconf.protocolor.icmpPx = GetColor(X.disp, gconf.protocolor.icmp);
	gconf.globehlcolor = strdup(gconf.globehlcolor);	// convert rdata to heap.
	gconf.globehlcolorPx = GetColor(X.disp, gconf.globehlcolor);
	gconf.globegridcolor = strdup(gconf.globegridcolor);	// convert rdata to heap.
	gconf.globegridcolorPx = GetColor(X.disp, gconf.globegridcolor);
	gconf.globeinterncolor = strdup(gconf.globeinterncolor);	// convert rdata to heap.
	gconf.globeinterncolorPx = GetColor(X.disp, gconf.globeinterncolor);

	// set status
	gstat.lasttime = (int)get_time();
	gstat.fps = 0;
	gstat.points = 0;
	gstat.curframespersec = 0;
	gstat.curpointspersec = 0;

	// set root info
	nroot.parent = NULL;
	nroot.child = NULL;
	nroot.next = NULL;
	nroot.leafs = 0;
	nroot.childs = 0;
	nroot.ping = 0;
	nroot.resolved = 0;
	nroot.tracerouted = 1;
	nroot.pingfail = 0;
	nroot.tradd = get_time();
	nroot.packet[0] = NULL;
	nroot.packet[1] = NULL;
	nroot.packet[2] = NULL;
	nroot.posinfo.deg = 0.0;
	nroot.cityindex = -1;

	resolveAdd(&nroot);

	logstr(0, "WELCOME: The net is vast and infinite...");
	logstr(0, "WELCOME: Load state or switch autonode on please.");

	{
		struct stat st;

		if(stat("autoexec", &st) == 0)
		{
			char *args[] = {"source", "autoexec"};
			cmdSource(2, args);
		}
	}

	for(;;)
	{
		if(pd)
			pcap_dispatch(pd, gconf.pktdispatchcnt, packetHandler, NULL);

		if(checkXevents() || gstat.quitting)
			break;

		doFrame();
	}

	puts("QUIT");

	XUnmapWindow(X.disp, X.wnd);
	XFlush(X.disp);

	if(pthTraceRunner)
	{
		puts("Waiting trace thread suiciding...");

		pthread_mutex_lock(&pmTraces);
		ctraces = 0;
		pthread_mutex_unlock(&pmTraces);
		pthread_join(pthTraceRunner, NULL);
	}
	if(pthResolveRunner)
	{
		puts("Waiting resolve thread suiciding...");

		pthread_mutex_lock(&pmResolves);
		cresolves = 0;
		pthread_mutex_unlock(&pmResolves);
		pthread_join(pthResolveRunner, NULL);
	}

	puts("Closing all resources... Fake! XD");

	if(pd)
		pcap_close(pd);
	XCloseDisplay(X.disp);

	puts("Good bye.");

	return 0;
}
