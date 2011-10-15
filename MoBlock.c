/*
 * MoBlock.c - Morpheus' Blocker
 *
 * Copyright (C) 2004 Morpheus (ebutera at users.berlios.de)
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <signal.h>
#include <regex.h>
#include <time.h>
#include <syslog.h>

// in Makefile define LIBIPQ to use soon-to-be-deprecated ip_queue,
// NFQUEUE for ipt_NFQUEUE (from kernel 2.6.14)

#ifdef LIBIPQ
	#include <libipq.h>
#endif
#ifdef NFQUEUE
	#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#define MB_VERSION	"0.9rc2"

#define BUFSIZE		2048
#define PAYLOADSIZE	21
#define BNAME_LEN	80

#define IS_UDP (packet->payload[9] == 17)
#define IS_TCP (packet->payload[9] == 6)

#define SRC_ADDR(payload) (*(in_addr_t *)((payload)+12))
#define DST_ADDR(payload) (*(in_addr_t *)((payload)+16))

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

// rbt datatypes/functions

typedef enum {
    STATUS_OK,
    STATUS_MEM_EXHAUSTED,
    STATUS_DUPLICATE_KEY,
    STATUS_KEY_NOT_FOUND,
	STATUS_MERGED,
	STATUS_SKIPPED
} statusEnum;
                
typedef unsigned long keyType;            /* type of key */
                
typedef struct {
    char blockname[BNAME_LEN];                  /* data */
    unsigned long ipmax;
    int hits;
} recType;   

extern statusEnum find(keyType key, recType *rec);
extern statusEnum find2(keyType key1, keyType key2, recType *rec);
extern statusEnum insert(keyType key, recType *rec);
extern void ll_show(FILE *logf);
extern void ll_log();
extern void ll_clear();
extern void destroy_tree();

// end of headers

FILE *logfile;
char *logfile_name=NULL;
const char* pidfile_name="/var/run/moblock.pid";

struct {			//holds list type and filename
	enum { LIST_DAT = 0, LIST_PG1, LIST_PG2} type;
	char filename[100];
} blocklist_info;

u_int32_t merged_ranges=0, skipped_ranges=0, accept_mark=0, reject_mark=0;
u_int8_t log2syslog=0, log2file=0, log2stdout=0, timestamp=0;

#ifdef LIBIPQ
static void die(struct ipq_handle *h)
{
	ipq_perror("MoBlock");
        ipq_destroy_handle(h);
		exit(-1);
}
#endif

char *ip2str(in_addr_t ip)
{
	static char buf[2][ sizeof("aaa.bbb.ccc.ddd") ];
	static short int index=0;
	
	ip = ntohl(ip);
	
	sprintf(buf[index],"%d.%d.%d.%d",
			(ip >> 24) & 0xff,
			(ip >> 16) & 0xff,
			(ip >> 8) & 0xff,
			(ip) & 0xff);
	
	if (index) {
		index=0;
		return buf[1];
	}
	else return buf[index++];
}

void print_addr( FILE *f, in_addr_t ip, int port )
{
	if (port == -1)
		fprintf(f, "%s:*", ip2str(ip));
	else
		fprintf(f, "%s:%d", ip2str(ip), port);
	fflush(stdout);
}

void log_action(char *msg)
{
	char timestr[30];
	time_t tv;

	if (timestamp) {
		tv = time(NULL);
		strncpy(timestr, ctime(&tv), 19);
		timestr[19] = '\0';
		strcat(timestr, "| ");
	}
	else strcpy(timestr, "");

	if (log2syslog) {
		syslog(LOG_INFO, msg);
	}

	if (log2file) {
		fprintf(logfile,"%s%s",timestr,msg);
		fflush(logfile);
	}

	if (log2stdout) {
		fprintf(stdout,"%s%s",timestr,msg);
	}
}

inline void ranged_insert(char *name,char *ipmin,char *ipmax)
{
    recType tmprec;
    int ret;
    char msgbuf[255];

	if ( strlen(name) > (BNAME_LEN-1) ) {
		strncpy(tmprec.blockname, name, BNAME_LEN);
		tmprec.blockname[BNAME_LEN-1]='\0';	
	}
	else strcpy(tmprec.blockname,name);
    tmprec.ipmax=ntohl(inet_addr(ipmax));
    tmprec.hits=0;
    if ( (ret=insert(ntohl(inet_addr(ipmin)),&tmprec)) != STATUS_OK  )
        switch(ret) {
            case STATUS_MEM_EXHAUSTED:
                log_action("Error inserting range, MEM_EXHAUSTED.\n");
                break;
            case STATUS_DUPLICATE_KEY:
                sprintf(msgbuf,"Duplicated range ( %s )\n",name);
                log_action(msgbuf);
                break;
			case STATUS_MERGED:
				merged_ranges++;
				break;
			case STATUS_SKIPPED:
				skipped_ranges++;
				break;
            default:
                log_action("Unexpected return value from ranged_insert()!\n");
                sprintf(msgbuf,"Return value was: %d\n",ret);
                log_action(msgbuf);
                break;
        }                
}

void loadlist_pg1(char* filename)
{
	FILE *fp;
	ssize_t count;
	char *line = NULL;
        size_t len = 0;
	int ntot=0;
	regex_t regmain;
	regmatch_t matches[4];
	int i;
	char msgbuf[255];

	regcomp(&regmain, "^(.*)[:]([0-9.]*)[-]([0-9.]*)$", REG_EXTENDED);

	fp=fopen(filename,"r");
	if ( fp == NULL ) {
		sprintf(msgbuf,"Error opening %s, aborting...\n", filename);
		log_action(msgbuf);
		exit(-1);
	}
	while ( (count=getline(&line,&len,fp)) != -1 ) {
		if ( line[0] == '#' )		//comment line, skip
			continue;
		for(i=count-1; i>=0; i--) {
			if ((line[i] == '\r') || (line[i] == '\n') || (line[i] == ' ')) {
				line[i] = 0;
			} else {
				break;
			}
		}
	   
		if (strlen(line) == 0)
			continue;

		if (!regexec(&regmain, line, 4, matches, 0)) {
			line[matches[1].rm_eo] = 0;
			line[matches[2].rm_eo] = 0;
			line[matches[3].rm_eo] = 0;

			ranged_insert(line+matches[1].rm_so, 
				      line+matches[2].rm_so, 
				      line+matches[3].rm_so);
			ntot++;
		} else {
			sprintf(msgbuf,"Short guarding.p2p line %s, skipping it...\n", line);
			log_action(msgbuf);
		}
	}
	if (line)
		free(line);
	fclose(fp);
	sprintf(msgbuf, "* Ranges loaded: %d\n", ntot);
	log_action(msgbuf);
	if ( !log2stdout )
		printf(msgbuf);
}

void loadlist_pg2(char *filename)		// supports only v2 files
{
    FILE *fp;
    int i, j, c, retval=0, ntot=0;
    char name[100],ipmin[16], msgbuf[255];	// hope we don't have a list with longer names...
    uint32_t start_ip, end_ip;
    struct in_addr startaddr,endaddr;
	size_t s;

    fp=fopen(filename,"r");
    if ( fp == NULL ) {
        sprintf(msgbuf, "Error opening %s, aborting...\n", filename);
        log_action(msgbuf);
        exit(-1);
    }

	for (j=0; j<4; j++) {
		c=fgetc(fp);
		if ( c != 0xff ) {
			sprintf(msgbuf,"Byte %d: 0x%x != 0xff, aborting...\n", j+1, c);
			log_action(msgbuf);
			fclose(fp);
			exit(-1);
		}
	}
	
	c=fgetc(fp);
	if ( c != 'P' ) {
		sprintf(msgbuf,"Byte 5: %c != P, aborting...\n", c);
		log_action(msgbuf);
		fclose(fp);
		exit(-1);
	}

	c=fgetc(fp);
	if ( c != '2' ) {
		sprintf(msgbuf,"Byte 6: %c != 2, aborting...\n", c);
		log_action(msgbuf);
		fclose(fp);
		exit(-1);
	}

	c=fgetc(fp);
	if ( c != 'B' ) {
		sprintf(msgbuf,"Byte 7: %c != B, aborting...\n", c);
		log_action(msgbuf);
		fclose(fp);
		exit(-1);
	}

	c=fgetc(fp);
	if ( c != 0x02 ) {
		sprintf(msgbuf,"Byte 8: version: %d != 2, aborting...\n", c);
		log_action(msgbuf);
		fclose(fp);
		exit(-1);
	}

	do {
        i=0;
        do {
            name[i]=fgetc(fp);
            i++;
        } while ( name[i-1] != 0x00 && name[i-1] != EOF);
        if ( name[i-1] != EOF ) {
            name[i-1]='\0';
			s=fread(&start_ip,4,1,fp);
			if ( s != 1 ) {
				sprintf(msgbuf,"Failed to read start IP: %d != 1, aborting...\n", (int)s);
				log_action(msgbuf);
                fclose(fp);
                exit(-1);
            }
            s=fread(&end_ip,4,1,fp);
            if ( s != 1 ) {
                sprintf(msgbuf,"Failed to read end IP: %d != 1, aborting...\n", (int)s);
				log_action(msgbuf);
                fclose(fp);
                exit(-1);
            }
			
			startaddr.s_addr=start_ip;
            endaddr.s_addr=end_ip;
            strcpy(ipmin,inet_ntoa(startaddr));
            ranged_insert(name,ipmin,inet_ntoa(endaddr));
            ntot++;
        }
        else {
            retval=EOF;
        }
    } while ( retval != EOF );
    fclose(fp);
    sprintf(msgbuf, "* Ranges loaded: %d\n",ntot);
    log_action(msgbuf);
	if ( !log2stdout )
		printf(msgbuf);
}

void loadlist_dat(char *filename)
{
    FILE *fp;
    int ntot=0;
    char readbuf[200], *name, start_ip[16], end_ip[16], msgbuf[255];
    unsigned short ip1_0, ip1_1, ip1_2, ip1_3, ip2_0, ip2_1, ip2_2, ip2_3;
    
    fp=fopen(filename,"r");
    if ( fp == NULL ) {
        sprintf(msgbuf,"Error opening %s, aborting...\n", filename);
        log_action(msgbuf);
        exit(-1);
    }
    
    while ( fgets(readbuf,200,fp) != NULL ) {
        if ( readbuf[0] == '#') continue;		// comment line, skip
        sscanf(readbuf,"%hd.%hd.%hd.%hd - %hd.%hd.%hd.%hd ,", &ip1_0, &ip1_1, &ip1_2, &ip1_3,
                                                            &ip2_0, &ip2_1, &ip2_2, &ip2_3);
        name=readbuf+42;
        name[strlen(name)-2]='\0';		// strip ending \r\n
        sprintf(start_ip,"%d.%d.%d.%d",ip1_0, ip1_1, ip1_2, ip1_3);
        sprintf(end_ip,"%d.%d.%d.%d",ip2_0, ip2_1, ip2_2, ip2_3);
        ranged_insert(name, start_ip, end_ip);
        ntot++;
    }
    fclose(fp);
    sprintf(msgbuf, "* Ranges loaded: %d\n", ntot);
    log_action(msgbuf);
	if ( !log2stdout )
		printf(msgbuf);
}

void reopen_logfile(void)
{
	char msgbuf[255];

	if (logfile != NULL) {
        	fclose(logfile);
		logfile=NULL;
	}
	logfile=fopen(logfile_name,"a");
	if (logfile == NULL) {
		sprintf(msgbuf, "Unable to open logfile %s\n", logfile_name);
		log_action(msgbuf);
		exit(-1);
	}
	log_action("Reopening logfile.\n");
}

void my_sahandler(int sig)
{
	char msgbuf[255];

	switch( sig ) {
        	case SIGUSR1:
			log_action("Got SIGUSR1! Dumping stats...\n");
			ll_show(logfile);
			reopen_logfile();
			break;
		case SIGUSR2:
			log_action("Got SIGUSR2! Dumping stats to /var/log/MoBlock.stats\n");
			ll_log();
			break;
		case SIGHUP:
			log_action("Got SIGHUP! Dumping and resetting stats, reloading blocklist\n");
			ll_log();
			ll_clear();		// clear stats list
			destroy_tree();		// clear loaded ranges
			switch (blocklist_info.type) {
				case LIST_DAT:
					loadlist_dat(blocklist_info.filename);
					break;
				case LIST_PG1:
					loadlist_pg1(blocklist_info.filename);
					break;
				case LIST_PG2:
					loadlist_pg2(blocklist_info.filename);
					break;
				default:
					log_action("Unknown blocklist type while reloading list, contact the developer!\n");
					break;
			}
			reopen_logfile();
			break;
		case SIGTERM:
			log_action("Got SIGTERM! Dumping stats and exiting.\n");
			ll_log();
			exit(0);
		default:
			sprintf(msgbuf,"Received signal = %d but not handled\n",sig);
			log_action(msgbuf);
			break;
	}
}

void init_sa()
{
    struct sigaction my_sa;
    
    my_sa.sa_handler=my_sahandler;
    my_sa.sa_flags=SA_RESTART;
    
    if ( sigaction(SIGUSR1,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGUSR1\n");
        exit(-1);
    }
    if ( sigaction(SIGUSR2,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGUSR2\n");
        exit(-1);
    }
    if ( sigaction(SIGHUP,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGHUP\n");
        exit(-1);
    }
    if ( sigaction(SIGTERM,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGTERM\n");
        exit(-1);
    }
}

#ifdef NFQUEUE
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
						struct nfq_data *nfa, void *data)
{
	int id=0, status=0;
	struct nfqnl_msg_packet_hdr *ph;
	char *payload, msgbuf[255];
	recType tmprec;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		nfq_get_payload(nfa, &payload);

		switch (ph->hook) {
			case NF_IP_LOCAL_IN:
				if ( find(ntohl(SRC_ADDR(payload)),&tmprec) == STATUS_OK ) {
					// we drop the packet instead of rejecting
					// we don't want the other host to know we are alive
					status=nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					sprintf(msgbuf,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR(payload)));
					log_action(msgbuf);
				}
				else if ( unlikely(accept_mark) ) {
					// we set the user-defined accept_mark and set NF_REPEAT verdict
					// it's up to other iptables rules to decide what to do with this marked packet
					status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
				     }
				     else {
				     	// no accept_mark, just NF_ACCEPT the packet
				     	status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				     }
				break;
			case NF_IP_LOCAL_OUT:
				if ( find(ntohl(DST_ADDR(payload)),&tmprec) == STATUS_OK ) {
					if ( likely(reject_mark) ) {
						// we set the user-defined reject_mark and set NF_REPEAT verdict
						// it's up to other iptables rules to decide what to do with this marked packet
						status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
					}
					else {
						status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					}
					sprintf(msgbuf,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR(payload)));
					log_action(msgbuf);
				}
				else if ( unlikely(accept_mark) ) {
					// we set the user-defined accept_mark and set NF_REPEAT verdict
					// it's up to other iptables rules to decide what to do with this marked packet
 				        status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
				     }
				     else {
					// no accept_mark, just NF_ACCEPT the packet
					status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				     }
				break;
			case NF_IP_FORWARD:
				if ( find2(ntohl(SRC_ADDR(payload)), ntohl(DST_ADDR(payload)), &tmprec) == STATUS_OK ) {
					if ( likely(reject_mark) ) {
						// we set the user-defined reject_mark and set NF_REPEAT verdict
						// it's up to other iptables rules to decide what to do with this marked packet
						status = nfq_set_verdict_mark(qh, id, NF_REPEAT, reject_mark, 0, NULL);
					}
					else {
						status = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					}
					sprintf(msgbuf,"Blocked FWD: %s,hits: %d,SRC: %s, DST: %s\n",
								tmprec.blockname, tmprec.hits, ip2str(SRC_ADDR(payload)), ip2str(DST_ADDR(payload)));
					log_action(msgbuf);
				}
				else if ( unlikely(accept_mark) ) {
					// we set the user-defined accept_mark and set NF_REPEAT verdict
					// it's up to other iptables rules to decide what to do with this marked packet
					status = nfq_set_verdict_mark(qh, id, NF_REPEAT, accept_mark, 0, NULL);
				     }
				     else {
				     	// no accept_mark, just NF_ACCEPT the packet
					status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				     }
				break;
			default:
				log_action("Not NF_LOCAL_IN/OUT/FORWARD packet!\n");
				break;
		}
	}
	else {
		log_action("NFQUEUE: can't get msg packet header.\n");
		return(1);		// from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
	}
	return(0);
}
#endif

short int netlink_loop(unsigned short int queuenum)
{
#ifdef LIBIPQ		//use old libipq interface, deprecated

	struct ipq_handle *h;
	ipq_packet_msg_t *packet;
	int status=0;
	unsigned char buf[BUFSIZE];
	recType tmprec;        
	
	h = ipq_create_handle(0, PF_INET);
	if (!h) die(h);

	status = ipq_set_mode(h, IPQ_COPY_PACKET, PAYLOADSIZE);
	if (status < 0) die(h);
		
	do {
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0) die(h);

		switch (ipq_message_type(buf)) {
			case NLMSG_ERROR:
				fprintf(logfile, "Received error message %d\n", ipq_get_msgerr(buf));
				break;
			case IPQM_PACKET:
				packet=ipq_get_packet(buf);				
				switch ( packet->hook ) {
					case NF_IP_LOCAL_IN:
						if ( find(ntohl(SRC_ADDR(packet->payload)),&tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					case NF_IP_LOCAL_OUT:
						if ( find(ntohl(DST_ADDR(packet->payload)),&tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					case NF_IP_FORWARD:
						if ( find2(ntohl(SRC_ADDR(packet->payload)), ntohl(DST_ADDR(packet->payload)), &tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked FWD: %s,hits: %d,SRC: %s, DST: %s\n",
										tmprec.blockname, tmprec.hits, ip2str(SRC_ADDR(packet->payload)), ip2str(DST_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					default:
						fprintf(logfile,"Not NF_LOCAL_IN/OUT/FORWARD packet!\n");
						break;
				}
				if (status < 0) die(h);
				break;
			default:
				fprintf(logfile, "Unknown message type!\n");
				break;
                }
	} while (1);

	ipq_destroy_handle(h);
	return 0;
#endif

#ifdef NFQUEUE		// use new NFQUEUE interface ( from kernel 2.6.14 )

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd,rv;
	char buf[BUFSIZE], msgbuf[255];

	h = nfq_open();
	if (!h) {
		log_action("Error during nfq_open()\n");
		exit(-1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		log_action("error during nfq_unbind_pf()\n");
		//exit(-1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		log_action("Error during nfq_bind_pf()\n");
		exit(-1);
	}

	sprintf(msgbuf,"NFQUEUE: binding to queue '%hd'\n", queuenum);
	log_action(msgbuf);
	qh = nfq_create_queue(h,  queuenum, &nfqueue_cb, NULL);
	if (!qh) {
		log_action("error during nfq_create_queue()\n");
		exit(-1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, PAYLOADSIZE) < 0) {
		log_action("can't set packet_copy mode\n");
		exit(-1);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	log_action("NFQUEUE: unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	nfq_close(h);
	nfq_unbind_pf(h, AF_INET);
	return(0);
#endif

}

void print_options(void)
{
	printf("\nMoBlock %s by Morpheus",MB_VERSION);
	printf("\nSyntax: MoBlock -dnp <blocklist> [-q 0-65535] <logfile>\n\n");
	printf("\t-d\tblocklist is an ipfilter.dat file\n");
	printf("\t-n\tblocklist is a peerguardian 2.x file (.p2b)\n");
	printf("\t-p\tblocklist is a peerguardian file (.p2p)\n");
	printf("\t-q\t0-65535 NFQUEUE number (as specified in --queue-num with iptables)\n");
	printf("\t-r MARK\tmark packet with MARK instead of DROP\n");
	printf("\t-a MARK\tmark packet with MARK instead of ACCEPT\n");
	printf("\t-l\tlog to stdout\n");
	printf("\t-s\tlog to syslog\n");
	printf("\t-t\tlog timestamping\n\n");
}

void on_quit()
{
	unlink(pidfile_name);
}

int main(int argc, char **argv)
{
	int ret=0;
	unsigned short int queuenum=0;
	char msgbuf[255];

	if (argc < 3) {
		print_options();
		exit(-1);
	}
	if (access(pidfile_name,F_OK)==0) {
		fprintf(stderr,"pid file %s exists. Not starting",pidfile_name);
		exit(-1);
	}
	else {		//create pidfile
		FILE *pid_file;
		pid_t pid=getpid();
		pid_file=fopen(pidfile_name,"w");
		if (pid_file == NULL) {
			fprintf(stderr, "Unable to create pid_file\n");
			exit(-1);
		}
		fprintf(pid_file,"%i\n",pid);
		fclose(pid_file);
	}
	
	ret=atexit(on_quit);
	if ( ret ) {
		fprintf(stderr,"Cannot register exit function, terminating.\n");
		exit(-1);
	}

	init_sa();
	logfile=fopen(argv[argc-1],"a");
	if (logfile == NULL) {
	    fprintf(stderr, "Unable to open logfile %s\n", argv[argc-1]);
	    exit(-1);
	}
	logfile_name=malloc(strlen(argv[argc-1])+1);
	strcpy(logfile_name,argv[argc-1]);
	log2file = 1;
	printf("* Logging to %s\n",logfile_name);
	
	while (1) {		//scan command line options
		ret=getopt(argc, argv, "d:n:p:q:a:r:stl");
		if ( ret == -1 ) break;
		
		switch (ret) {
			case 'd':			// ipfilter.dat file format
				loadlist_dat(optarg);
				blocklist_info.type=LIST_DAT;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .dat file format\n");
				break;
			case 'n':			// peerguardian 2.x file format .p2b
				loadlist_pg2(optarg);
				blocklist_info.type=LIST_PG2;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .p2b file format\n");
				break;
			case 'p':			// peerguardian file format .p2p
				loadlist_pg1(optarg);
				blocklist_info.type=LIST_PG1;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .p2p file format\n");
				break;
			case 'q':
				queuenum=(unsigned short int)atoi(optarg);
				break;
			case 'r':
				reject_mark=(u_int32_t)atoi(optarg);
				printf("* DROP MARK: %d\n", reject_mark);
				reject_mark=htonl(reject_mark);
				break;
			case 'a':
				accept_mark=(u_int32_t)atoi(optarg);
				printf("* ACCEPT MARK: %d\n", accept_mark);
				accept_mark=htonl(accept_mark);
				break;
			case 's':
				log2syslog = 1;
				printf("* Logging to syslog\n");
				break;
			case 't':
				timestamp = 1;
				printf("* Log timestamp enabled\n");
				break;
			case 'l':
				log2stdout = 1;
				printf("* Log to stdout enabled\n");
				break;
			case '?':			// unknown option
				print_options();
				exit(-1);
				break;
		}
	}
	
	sprintf(msgbuf, "* Merged ranges: %d\n", merged_ranges);
	log_action(msgbuf);
	if ( !log2stdout )
		printf(msgbuf);
	sprintf(msgbuf,"* Skipped useless ranges: %d\n", skipped_ranges);
	log_action(msgbuf);
	if ( !log2stdout )
		printf(msgbuf);
	fflush(NULL);

	netlink_loop(queuenum);
	exit(0);
}
