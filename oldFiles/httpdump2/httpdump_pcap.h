#ifndef _HTTPDUMP_PCAP_
#define _HTTPDUMP_PCAP_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "httpdump_pkt.h"

uint32_t rotate_interval = 0;
uint32_t rotate_last = 0;
FILE *fp = NULL;

typedef struct {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    uint32_t thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t linktype;       /* data link type */
}pcap_file_header;

void httpdump_pcap (unsigned char *arg, const struct pcap_pkthdr *pkthdr, const unsigned char *bytes) {
    
    // Check minimum packet size
    // 14 (Ethernet) + 20 (IPv4) + 20 (TCP)
    if (pkthdr->len < 54)
        return;
    
    host_t src;
    host_t dst;
    memset(&src, 0, sizeof(host_t));
    memset(&dst, 0, sizeof(host_t));
    
    // Ethernet Header
    uint16_t i = 12;
    while ((bytes[i + 1] == 0x00 && (bytes[i] == 0x81 || bytes[i] == 0x91
                                     || bytes[i] == 0x92 || bytes[i] == 0x93))
           || (bytes[i] == 0x88 && bytes[i + 1] == 0xa8)) {
        // VLAN tagging
        // EtherType = 0x8100, 0x9100, 0x9200, 0x9300, 0x88a8
        i += 4;
        if (i > pkthdr->len - 40)
            return;
    }
    
    // IP Header
    if (bytes[i] == 0x08 && bytes[i + 1] == 0x00) {
        // IPv4
        i += 2;
        if ((bytes[i] & 0xF0) != 0x40) // Require: version = 4
            return;
        if (bytes[i + 9] != 6) // Require: protocol = 6 (TCP)
            return;
        src.ipver = 4;
        src.ip4 = be32toh(*(uint32_t *)&bytes[i + 12]);
        dst.ipver = 4;
        dst.ip4 = be32toh(*(uint32_t *)&bytes[i + 16]);
        i += (bytes[i] & 0x0F) << 2; // IHL
    } else if (bytes[i] == 0x86 && bytes[i + 1] == 0xDD) {
        // IPv6
        i += 2;
        if ((bytes[i] & 0xF0) != 0x60) // Require: version = 6
            return;
        /* TODO: IPv6 Extension Headers? */
        if (bytes[i + 6] != 6) // Require: next header = 6 (TCP)
            return;
        src.ipver = 6;
        src.ip6h = be64toh(*(uint64_t *)&bytes[i + 8]);
        src.ip6l = be64toh(*(uint64_t *)&bytes[i + 16]);
        dst.ipver = 6;
        dst.ip6h = be64toh(*(uint64_t *)&bytes[i + 24]);
        dst.ip6l = be64toh(*(uint64_t *)&bytes[i + 32]);
        i += 40;
    }
    
    if (i > pkthdr->len - 20)
        return;
    
    // TCP Header
    src.port = be16toh(*((uint16_t *)(bytes + i)));
    dst.port = be16toh(*((uint16_t *)(bytes + i + 2)));
    uint32_t seq = be32toh(*((uint32_t *)(bytes + i + 4)));
    i += (bytes[i + 12] & 0xF0) >> 2;
    
    if (i >= pkthdr->len)
        return;
    
    httpdump_pkt((unsigned char *)(bytes + i), seq, pkthdr->len - i, pkthdr->ts, &src, &dst, bytes, pkthdr->len, fp);
    
}

/*
 * Pcap Initialization
 */
void httpdump_start (char *dev, char *filename) {
	// Open file
    struct timeval now;
    if (fp == NULL || rotate_interval > 0) {
        gettimeofday(&now, NULL);
        if (rotate_interval > 0) {
            now.tv_sec = now.tv_sec - now.tv_sec % rotate_interval;
        }
    }
    if (rotate_interval > 0 && now.tv_sec != rotate_last) {
        rotate_last = now.tv_sec;
        if (fp != NULL) {
            fclose(fp);
            fp = NULL;
        }
    }
    if (fp == NULL) {
		if (filename == NULL){
			char filename[32];
			struct tm *now_tm = localtime(&(now.tv_sec));
			strftime(filename, sizeof filename, "%Y%m%d-%H%M%S.pcap", now_tm);
			fprintf(stdout, "Opening pcap file: %s\n", filename);
			fp = fopen(filename, "ab");
		}
		else{
			fprintf(stdout, "Opening pcap file: %s\n", filename);
			fp = fopen(filename, "ab");
		}
        if (fp == NULL) {
            fprintf(stderr, "Error: Unable to open file for appending: %s\n", filename);
            return stdout;
        }
    }
	
	//Write file header
	pcap_file_header * tmp_file_header = calloc(1, sizeof(pcap_file_header));
    tmp_file_header->magic_number = 0xa1b2c3d4;
    tmp_file_header->version_major = 0x0200;
    tmp_file_header->version_minor = 0x0400;
    tmp_file_header->thiszone = 0x00000000;
    tmp_file_header->sigfigs = 0x00000000;
    tmp_file_header->snaplen = 0xffff0000;
    tmp_file_header->linktype = 1;
	fwrite(tmp_file_header, sizeof(pcap_file_header), 1, fp);

	
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (dev == NULL) {
        // Use default device
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Error: cannot get default device: %s\n", errbuf);
            exit(1);
        }
    }
    
    printf("Opening device %s...\n", dev);
    
    pcap_t *handle;
    handle = pcap_create(dev, errbuf);
    
    if (handle == NULL) {
        
        // Try offline
        handle = pcap_open_offline(dev, errbuf);
        
        if (handle == NULL) {
            fprintf(stderr, "Error: cannot open device %s: %s\n", dev, errbuf);
            exit(1);
        }
        
    } else {
        
        // Live device
        //struct bpf_program fp;
        char filter_exp[] = "tcp";
        
        if (pcap_set_snaplen(handle, 65536) != 0) {
            fprintf(stderr, "Error: pcap_set_snaplen failed: %s\n", pcap_geterr(handle));
            exit(1);
        }
        if (pcap_set_timeout(handle, 1000) != 0) {
            fprintf(stderr, "Error: pcap_set_timeout failed: %s\n", pcap_geterr(handle));
            exit(1);
        }
        if (pcap_set_buffer_size(handle, 104857600) != 0) {
            fprintf(stderr, "Error: pcap_set_buffer_size failed: %s\n", pcap_geterr(handle));
            exit(1);
        }
        if (pcap_set_promisc(handle, 1) != 0) {
            fprintf(stderr, "Error: pcap_set_promisc failed: %s\n", pcap_geterr(handle));
            exit(1);
        }
        if (pcap_activate(handle) != 0) {
            fprintf(stderr, "Error: pcap_activate failed: %s\n", pcap_geterr(handle));
            exit(1);
        }
        
        /*bpf_u_int32 net;
        bpf_u_int32 mask;
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Error: cannot get netmask for device %s: %s\n", dev, errbuf);
            net = 0;
            mask = 0;
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Error: cannot compile pcap filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(1);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error: cannot set pcap filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(1);
        }*/
    }
    
    pcap_loop(handle, -1, httpdump_pcap, NULL);
    
    /* if (hashtable_old) {
        record_t *record, *tmp;
        HASH_ITER(hh, hashtable_old, record, tmp) {
            httpdump_http(record->data, REASM_MAX_LENGTH, record->ts, &(record->key.src), &(record->key.dst), rdata, rlen, fp);
            HASH_DEL(hashtable_old, record);
            free(record);
        }
    }
    hashtable_old = NULL;
    if (hashtable) {
        record_t *record, *tmp;
        HASH_ITER(hh, hashtable, record, tmp) {
            httpdump_http(record->data, REASM_MAX_LENGTH, record->ts, &(record->key.src), &(record->key.dst));
            HASH_DEL(hashtable, record);
            free(record);
        }
    }
    hashtable = NULL; */
    
}

#endif //_HTTPDUMP_PCAP_

