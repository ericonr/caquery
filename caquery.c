/* Based on https://epics.anl.gov/base/R3-15/6-docs/CAproto/index.html */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CA_PROTO_VERSION 0x0
#define CA_PROTO_SEARCH 0x6

#define DESIRED_PRIORITY 1
#define CA_VERSION 13

static inline uint16_t get_net_u16(const unsigned char *p)
{
	uint16_t b0 = p[0], b1 = p[1];
	return b0 << 8 | b1;
}

static inline uint32_t get_net_u32(const unsigned char *p)
{
	uint32_t b0 = p[0], b1 = p[1], b2 = p[2], b3 = p[3];
	return b0 << 24 | b1 << 16 | b2 << 8 | b3;
}

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
	msg[0] = 0;
	msg[1] = CA_PROTO_VERSION;
	/* payload size */
	msg[2] = 0;
	msg[3] = 0;
	/* priority */
	msg[4] = 0;
	msg[5] = DESIRED_PRIORITY;
	/* version 4.13 */
	msg[6] = 0;
	msg[7] = CA_VERSION;
	/* parameter 1; CA_PROTO_VERSION 0 */
	msg[8] = msg[9] = msg[10] = msg[11] = 0;
	/* parameter 2; CA_PROTO_VERSION 0 */
	msg[12] = msg[13] = msg[14] = msg[15] = 0;
	/* XXX: why does caget do this? */
	//msg[11] = 1;

	msg[16] = 0;
	msg[17] = CA_PROTO_SEARCH;
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
	if (sendto(fd, msg, total_len + padding, 0, (struct sockaddr *)&addr, sizeof addr) != total_len + padding) {
		perror("sendto");
		return 1;
	}

	socklen_t addrlen = sizeof addr;

	unsigned response_counter = 0;
	struct pollfd response_poll = {.fd = fd, .events = POLLIN};
	while (poll(&response_poll, 1, response_counter ? 500 : 2000) > 0) {
		if (response_poll.revents & POLLERR)
			break;

		response_counter++;
		if (recvfrom(fd, msg, sizeof msg, 0, (struct sockaddr *)&addr, &addrlen) < 0) {
			perror("recvfrom");
			continue;
		}

		const unsigned char *pmsg = msg;

		if (get_net_u16(pmsg) != CA_PROTO_VERSION) {
			fputs("version: bad command\n", stderr);
			continue;
		} else if (get_net_u16(pmsg+4) != DESIRED_PRIORITY) {
			/* XXX: spec says this should be 0 */
			fputs("version: bad priority\n", stderr);
			continue;
		} else if (get_net_u16(pmsg+6) != CA_VERSION) {
			fputs("version: unexpected version\n", stderr);
			continue;
		}

		pmsg += 16;
		if (get_net_u16(pmsg) != CA_PROTO_SEARCH) {
			fputs("search: bad command\n", stderr);
			continue;
		} else if (get_net_u16(pmsg+2) != 8) {
			fputs("search: bad payload size\n", stderr);
			continue;
		} else if (get_net_u16(pmsg+6) != 0) {
			fputs("search: bad data count\n", stderr);
			continue;
		} else if (get_net_u32(pmsg+12) != sid) {
			fputs("search: bad SearchID\n", stderr);
			continue;
		}

		char server_ip[INET_ADDRSTRLEN];
		if (get_net_u32(pmsg+8) == 0xffffffff) {
			inet_ntop(AF_INET, &addr.sin_addr, server_ip, sizeof server_ip);
		} else {
			struct in_addr tmp_addr;
			memcpy(&tmp_addr.s_addr, pmsg+8, sizeof tmp_addr.s_addr);
			inet_ntop(AF_INET, &tmp_addr, server_ip, sizeof server_ip);
		}

		uint16_t server_port = get_net_u16(pmsg+4);
		/* payload */
		uint16_t server_proto_version = get_net_u16(pmsg+16);

		printf("server: %s port: %u version: 4.%u\n", server_ip, server_port, server_proto_version);
	}

	fprintf(stderr, "number of responses: %u\n", response_counter);
}
