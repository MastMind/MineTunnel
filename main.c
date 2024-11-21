#include <stdio.h>

#include "tunnel.h"




int main(int argc, char** argv) {
	if (tunnel_parse_opts(argc, argv)) {
		fprintf(stderr, "Error in options. Use -h for help\n");
		return -1;
	}

	if (tunnel_app_start()) {
		fprintf(stderr, "Can't start tunnel\nUse -v option for more information\n");
		return -2;
	}

	tunnel_app_stop();

	return 0;
}
