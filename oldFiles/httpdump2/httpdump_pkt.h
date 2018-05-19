#ifndef _HTTPDUMP_PKT_
#define _HTTPDUMP_PKT_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t ipver;
    uint32_t ip4;
    uint64_t ip6h;
    uint64_t ip6l;
    uint16_t port;
} host_t;

#include "httpdump_http.h"
#include "uthash.h"

typedef struct {
    host_t src;
    host_t dst;
} hostpair_t;

#define REASM_MAX_LENGTH 65536
#define CACHE_FLUSH_TIME 8

typedef struct {
    hostpair_t key;
    struct timeval ts;
    uint32_t initialseq;
    uint32_t nextseq;
    char data[REASM_MAX_LENGTH];
    UT_hash_handle hh;
} record_t;

record_t *hashtable = NULL;
record_t *hashtable_old = NULL;
uint64_t cache_time = 0;

void httpdump_pkt (unsigned char *data, uint32_t seq, uint16_t len, struct timeval ts, host_t *src, host_t *dst, unsigned char *rdata, uint16_t rlen, FILE *fp) {
    
    if (len > HTTP_HEADER_MINLEN && (
            strncmp(data, "GET ", 4) == 0 ||
    	    strncmp(data, "POST ", 5) == 0 ||
    	    strncmp(data, "HEAD ", 5) == 0 ||
    	    strncmp(data, "CONNECT ", 8) == 0 ||
    	    strncmp(data, "OPTIONS ", 8) == 0 ||
    	    strncmp(data, "PUT ", 4) == 0 ||
    	    strncmp(data, "DELETE ", 7) == 0 ||
        	strncmp(data, "TRACE ", 6) == 0 ||
            strncmp(data, "PATCH ", 6) == 0 ||
            strncmp(data, "SEARCH ", 7) == 0 ||
            strncmp(data, "MOVE ", 5) == 0 ||
            strncmp(data, "COPY ", 5) == 0 ||
            strncasecmp(data, "HTTP/1.", 7) == 0
    )) { // New
        printf("Writing a packet.\n");
		pcap_frame_header * tmp_frame_header = calloc(1, sizeof(pcap_frame_header));
		time_t t;
		t = time(NULL);
		tmp_frame_header->ts_sec = time(&t);
		tmp_frame_header->ts_usec = 0;
		tmp_frame_header->incl_len = rlen;
		tmp_frame_header->orig_len = rlen;
		fwrite(tmp_frame_header, sizeof(pcap_frame_header), 1, fp);
		fwrite(rdata, 1, rlen, fp);
        //if (memmem(data, len, "\r\n\r\n", 4) != NULL) {
        //    httpdump_http(data, len, ts, src, dst, rdata, rlen, fp);
        //}
	}
}	/*else {
            record_t *record = calloc(1, sizeof(record_t));
            memcpy(&(record->key.src), src, sizeof(host_t));
            memcpy(&(record->key.dst), dst, sizeof(host_t));
            record_t *found = NULL;
            record_t **table = &hashtable;
            HASH_FIND(hh, hashtable, &(record->key), sizeof(hostpair_t), found);
            if (!found) {
                HASH_FIND(hh, hashtable_old, &(record->key), sizeof(hostpair_t), found);
                table = &hashtable_old;
            }
            if (found && found->initialseq == seq) { // Retransmission
                free(record);
            } else {
                if (found) {
                    httpdump_http(found->data, REASM_MAX_LENGTH, found->ts, src, dst, rdata, rlen, fp);
                    HASH_DEL(*table, found);
                    free(found);
                }
                record->ts = ts;
                record->initialseq = seq;
                record->nextseq = seq + len;
                memcpy(record->data, data, len);
                HASH_ADD(hh, hashtable, key, sizeof(hostpair_t), record);
            }
        }
        
    } else {
        
        hostpair_t key;
        memset(&key, 0, sizeof(hostpair_t));
        memcpy(&(key.src), src, sizeof(host_t));
        memcpy(&(key.dst), dst, sizeof(host_t));
        
        record_t *record = NULL;
        record_t **table = &hashtable;
        HASH_FIND(hh, hashtable, &key, sizeof(hostpair_t), record);
        if (!record) {
            HASH_FIND(hh, hashtable_old, &key, sizeof(hostpair_t), record);
            table = &hashtable_old;
        }
        if (record) {
            uint32_t offset = seq - record->initialseq;
            if (seq > record->initialseq && offset < REASM_MAX_LENGTH) {
                memcpy(record->data + offset, data, len < REASM_MAX_LENGTH - offset ? len : REASM_MAX_LENGTH - offset);
                if (record->nextseq == seq) {
                    record->nextseq = seq + len;
                    if (memmem(data, len, "\r\n\r\n", 4) != NULL) {
                        httpdump_http(record->data, REASM_MAX_LENGTH, record->ts, src, dst, rdata, rlen, fp);
                        HASH_DEL(*table, record);
                        free(record);
                    }
                } else { // Out of order
                    record->nextseq = 0;
                }
            }
        }
        
    }
    
    uint64_t ctime = ts.tv_sec - ts.tv_sec % CACHE_FLUSH_TIME;
    if (ctime != cache_time) {
        cache_time = ctime;
        if (hashtable_old) {
            record_t *record, *tmp;
            HASH_ITER(hh, hashtable_old, record, tmp) {
                httpdump_http(record->data, REASM_MAX_LENGTH, record->ts, &(record->key.src), &(record->key.dst), rdata, rlen, fp);
                HASH_DEL(hashtable_old, record);
                free(record);
            }
        }
        hashtable_old = hashtable;
        hashtable = NULL;
    }
    
}*/

#endif //_HTTPDUMP_PKT_

