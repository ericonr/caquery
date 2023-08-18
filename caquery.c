/* Based on https://epics.anl.gov/base/R3-15/6-docs/CAproto/index.html */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main (int argc, char **argv)
{
	if (argc < 3) return 1;

	const char *host = argv[1];
	const char *pv_name = argv[2];

	struct in_addr ip;
	if (inet_pton(AF_INET, host, &ip) != 1) {
		fputs("bad IP addr\n", stderr);
		/* TODO: try getaddrinfo */
		return 1;
	}

	struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(5064), .sin_addr=ip};
	struct sockaddr_in own_addr = {.sin_family=AF_INET, .sin_port=0, .sin_addr={0}};
	
	size_t pv_name_len = strlen(pv_name);
	size_t total_len = 32 + pv_name_len;
	size_t padding = (total_len / 8 + 1) * 8 - total_len;
	if (pv_name_len + padding > 0x4000) {
		fputs("pv name too long\n", stderr);
		return 1;
	}

	uint32_t sid = 123456789;

	unsigned char msg[512];
	/* command; CA_PROTO_VERSION 0x0 */
	msg[0] = 0;
	msg[1] = 0;
	/* payload size */
	msg[2] = 0;
	msg[3] = 0;
	/* priority */
	msg[4] = 0;
	msg[5] = 1;
	/* version 4.13 */
	msg[6] = 0;
	msg[7] = 13;
	/* parameter 1; CA_PROTO_VERSION 0 */
	msg[8] = msg[9] = msg[10] = msg[11] = 0;
	/* parameter 2; CA_PROTO_VERSION 0 */
	msg[12] = msg[13] = msg[14] = msg[15] = 0;
	/* XXX: why does caget do this? */
	//msg[11] = 1;

	/* command; CA_PROTO_SEARCH 0x6 */
	msg[16] = 0;
	msg[17] = 6;
	/* payload size */
	msg[18] = (pv_name_len + padding) >> 8;
	msg[19] = (pv_name_len + padding) & 0xff;
	/* reply flag; DO_NOT_REPLY 0x5 */
	msg[20] = 0;
	msg[21] = 5;
	/* version 4.13 */
	msg[22] = 0;
	msg[23] = 13;
	/* parameter 1; CA_PROTO_SEARCH SID */
	msg[24] = sid >> 24;
	msg[25] = (sid >> 16) & 0xff;
	msg[26] = (sid >> 8) & 0xff;
	msg[27] = sid & 0xff;
	/* parameter 2; CA_PROTO_SEARCH SID */
	msg[28] = msg[24];
	msg[29] = msg[25];
	msg[30] = msg[26];
	msg[31] = msg[27];

	memcpy(msg+32, pv_name, pv_name_len);
	memset(msg+32+pv_name_len, 0, padding);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bind(fd, (struct sockaddr *)&own_addr, sizeof own_addr)) {
		perror("bind");
		return 1;
	}
	sendto(fd, msg, total_len + padding, 0, (struct sockaddr *)&addr, sizeof addr);

	socklen_t addrlen = sizeof addr;

	unsigned response_counter = 0;
	struct pollfd response_poll = {.fd = fd, .events = POLLIN};
	while (poll(&response_poll, 1, 500) > 0) {
		response_counter++;
		/* TODO: implement reading response */
		recvfrom(fd, msg, sizeof msg, 0, (struct sockaddr *)&addr, &addrlen);
	}

	fprintf(stderr, "number of responses: %u\n", response_counter);
}
