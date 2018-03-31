#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "httpdump_catch.h"

void usage (char *progname) {
    printf("Usage: %s [-i <interface>] [-r <file>] [-G <rotate_seconds>]\n", progname);
}

int main (int argc, char *argv[]) {
    
    char *dev = NULL;
	char *filename = NULL;
    
    int c;
    while ((c = getopt(argc, argv, "hi:r:G:")) != -1) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'i':
                dev = optarg;
                break;
            case 'r':
                filename = optarg;
                break;
            case 'G':
                rotate_interval = atoi(optarg);
                break;
        }
    }
    
    httpdump_start(dev, filename);
    
    return 0;
}
