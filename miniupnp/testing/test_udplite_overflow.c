/*
 * test_udplite_overflow.c
 *
 * Proof-of-concept for stack buffer overflow in miniupnpd
 * upnp_get_redirection_infos_by_index() when protocol is UDPLITE.
 *
 * The bug: upnpredirect.c:506 does memcpy(protocol, "UDPLITE", 8)
 * but tomato_save() and tomato_delete() in miniupnpd.c pass a
 * char proto[4] buffer. This writes 4 bytes past the buffer.
 *
 * This harness reproduces the exact stack layout of tomato_save()
 * and calls the vulnerable memcpy to demonstrate the overflow.
 *
 * Build:
 *   # Without stack protector (see silent corruption):
 *   gcc -o test_overflow test_udplite_overflow.c -fno-stack-protector
 *
 *   # With stack protector (see crash/abort):
 *   gcc -o test_overflow_protected test_udplite_overflow.c -fstack-protector-all
 *
 * Usage:
 *   ./test_overflow
 *   ./test_overflow_protected
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Hex dump a buffer with a label */
static void hexdump(const char *label, const void *buf, size_t len)
{
	const unsigned char *p = (const unsigned char *)buf;
	size_t i;
	printf("  %s (%zu bytes): ", label, len);
	for (i = 0; i < len; i++)
		printf("%02x ", p[i]);
	printf(" |");
	for (i = 0; i < len; i++)
		printf("%c", (p[i] >= 0x20 && p[i] < 0x7f) ? p[i] : '.');
	printf("|\n");
}

/*
 * Simulates the vulnerable code path from upnpredirect.c:502-509.
 * This is exactly what upnp_get_redirection_infos_by_index() does
 * after retrieving a redirect rule.
 */
static int simulate_get_redirection_infos(int proto_int, char *protocol)
{
	if (proto_int == IPPROTO_TCP)
		memcpy(protocol, "TCP", 4);
#ifdef IPPROTO_UDPLITE
	else if (proto_int == IPPROTO_UDPLITE)
		memcpy(protocol, "UDPLITE", 8);   /* THE BUG: 8 bytes into caller's 4-byte buffer */
#endif
	else
		memcpy(protocol, "UDP", 4);
	return 0;
}

/*
 * Reproduces the exact stack layout of tomato_save() from miniupnpd.c:144-181.
 * Variables are declared in the same order to match likely stack layout.
 */
static void test_tomato_save_layout(int proto_int)
{
	/* --- begin tomato_save() local variables, same declaration order --- */
	unsigned short eport;
	unsigned short iport;
	unsigned int leaseduration;
	unsigned int timestamp;
	char proto[4];          /* the undersized buffer */
	char iaddr[32];         /* adjacent on stack - overflow target */
	char desc[64];
	char rhost[32];
	int n;
	/* We skip FILE *f, int t, char tmp[128] as they're not relevant */
	/* --- end tomato_save() locals --- */

	/* Initialize with known patterns so we can see what gets corrupted */
	memset(proto, 'P', sizeof(proto));
	memset(iaddr, 'A', sizeof(iaddr));
	memset(desc, 'D', sizeof(desc));
	memset(rhost, 'R', sizeof(rhost));
	eport = 0x1111;
	iport = 0x2222;
	leaseduration = 0xAAAAAAAA;
	timestamp = 0xBBBBBBBB;
	n = 0x43434343;

	/* Simulate a real IP address in iaddr */
	strncpy(iaddr, "192.168.1.100", sizeof(iaddr) - 1);
	iaddr[sizeof(iaddr) - 1] = '\0';

	printf("=== BEFORE overflow (proto_int=%d) ===\n", proto_int);
	hexdump("proto[4]", proto, sizeof(proto));
	hexdump("iaddr[32]", iaddr, sizeof(iaddr));
	printf("  iaddr as string: \"%s\"\n", iaddr);
	printf("\n");

	/* This is the call that overflows */
	simulate_get_redirection_infos(proto_int, proto);

	printf("=== AFTER overflow ===\n");
	hexdump("proto[4]", proto, sizeof(proto));
	hexdump("iaddr[32]", iaddr, sizeof(iaddr));
	printf("  proto as string: \"%s\"\n", proto);
	printf("  iaddr as string: \"%s\"\n", iaddr);
	printf("\n");

	/* Show what tomato_save's fprintf would produce */
	printf("=== What tomato_save() would write to the save file ===\n");
	timestamp = (leaseduration > 0) ? leaseduration : 0;
	printf("  fprintf: \"%s %u %s %u [%s] %u\\n\"\n",
	       proto, (unsigned)eport, iaddr, (unsigned)iport, desc, timestamp);
	printf("\n");
}

/*
 * Also test with a struct to force adjacent layout,
 * removing any doubt about compiler reordering.
 */
struct tomato_frame {
	char proto[4];
	char iaddr[32];
};

static void test_packed_layout(int proto_int)
{
	struct tomato_frame frame;

	memset(&frame, 0, sizeof(frame));
	strncpy(frame.iaddr, "192.168.1.100", sizeof(frame.iaddr) - 1);

	printf("=== PACKED STRUCT TEST (guarantees adjacency) ===\n");
	printf("  proto  is at offset %zu\n", (size_t)((char *)&frame.proto - (char *)&frame));
	printf("  iaddr  is at offset %zu\n", (size_t)((char *)&frame.iaddr - (char *)&frame));
	printf("\n");

	printf("--- Before ---\n");
	hexdump("proto[4]", frame.proto, sizeof(frame.proto));
	hexdump("iaddr[32]", frame.iaddr, sizeof(frame.iaddr));
	printf("  iaddr: \"%s\"\n", frame.iaddr);
	printf("\n");

	simulate_get_redirection_infos(proto_int, frame.proto);

	printf("--- After ---\n");
	hexdump("proto[4]", frame.proto, sizeof(frame.proto));
	hexdump("iaddr[32]", frame.iaddr, sizeof(frame.iaddr));
	printf("  proto: \"%s\"\n", frame.proto);
	printf("  iaddr: \"%s\"\n", frame.iaddr);

	/* Check for corruption */
	if (strcmp(frame.iaddr, "192.168.1.100") != 0) {
		printf("\n  *** CORRUPTION DETECTED ***\n");
		printf("  iaddr was \"192.168.1.100\", now \"%s\"\n", frame.iaddr);
		printf("  The overflow wrote into adjacent memory.\n");
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	printf("miniupnpd UDPLITE Stack Buffer Overflow PoC\n");
	printf("============================================\n");
	printf("Bug: upnpredirect.c:506 writes memcpy(protocol, \"UDPLITE\", 8)\n");
	printf("     but tomato_save()/tomato_delete() pass char proto[4]\n");
	printf("\n");

	/* First, show that TCP and UDP are fine (fit in 4 bytes) */
	printf("--- Control test: TCP (4 bytes including null, fits in proto[4]) ---\n");
	test_packed_layout(IPPROTO_TCP);

	printf("--- Control test: UDP (4 bytes including null, fits in proto[4]) ---\n");
	test_packed_layout(IPPROTO_UDP);

	/* Now trigger the overflow */
	printf("--- OVERFLOW test: UDPLITE (8 bytes into 4-byte buffer) ---\n");
	test_packed_layout(IPPROTO_UDPLITE);

	/* Full stack layout reproduction */
	printf("============================================\n");
	printf("Full tomato_save() stack layout reproduction\n");
	printf("============================================\n");
	printf("\n--- Safe case: TCP ---\n");
	test_tomato_save_layout(IPPROTO_TCP);

	printf("--- Overflow case: UDPLITE ---\n");
	test_tomato_save_layout(IPPROTO_UDPLITE);

	return 0;
}
