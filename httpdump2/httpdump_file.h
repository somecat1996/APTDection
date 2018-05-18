#ifndef _HTTPDUMP_FILE_
#define _HTTPDUMP_FILE_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint32_t rotate_interval = 0;
uint32_t rotate_last = 0;
FILE *fp = NULL;

inline FILE *httpdump_file () {
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
        char filename[32];
        struct tm *now_tm = localtime(&(now.tv_sec));
        strftime(filename, sizeof filename, "%Y%m%d-%H%M%S.log", now_tm);
        fprintf(stdout, "Opening log file: %s\n", filename);
        fp = fopen(filename, "a");
        if (fp == NULL) {
            fprintf(stderr, "Error: Unable to open file for appending: %s\n", filename);
            return stdout;
        }
    }
    return fp;
}

#endif //_HTTPDUMP_FILE_

