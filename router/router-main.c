/* 
 * The main program for the Router.
 *
 * For the first part of the project, you may not change this.
 *
 * For the second part of the project, feel free to change as necessary.
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "router.h"
#include "ports.h"

// Debug logging - set to 1 to enable, 0 to disable
#define DEBUG_LOG 1

static void debug_log(const char *fmt, ...) {
    if (!DEBUG_LOG) return;
    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(stderr, "[ROUTER %02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void print_hex(const char *label, const unsigned char *data, int len) {
    if (!DEBUG_LOG) return;
    fprintf(stderr, "[ROUTER DEBUG] %s (%d bytes): ", label, len);
    int print_len = len > 64 ? 64 : len;
    for (int i = 0; i < print_len; i++) {
        fprintf(stderr, "%02x", data[i]);
    }
    if (len > 64) fprintf(stderr, "...(truncated)");
    fprintf(stderr, "\n");
}

int main(int argc, char**argv)
{
   int n;
   char mesg[1000];
   struct sockaddr_in incoming_addr;
   static unsigned long pkt_count = 0;

   Router *router = router_create();
   
   if (DEBUG_LOG) {
       fprintf(stderr, "\n========================================\n");
       fprintf(stderr, "[ROUTER] Started - Listening on port %d\n", ROUTER_PORT);
       fprintf(stderr, "[ROUTER] Will forward ATM (port %d) <-> Bank (port %d)\n", ATM_PORT, BANK_PORT);
       fprintf(stderr, "========================================\n\n");
   }

   while(1)
   {
       n = router_recv(router, mesg, 1000, &incoming_addr);
       pkt_count++;

       unsigned short incoming_port = ntohs(incoming_addr.sin_port);

       // Packet from the ATM: forward it to the bank
       if(incoming_port == ATM_PORT)
       {
           debug_log("PKT #%lu: ATM -> BANK (%d bytes)\n", pkt_count, n);
           print_hex("Raw packet", (unsigned char*)mesg, n);
           router_sendto_bank(router, mesg, n);
           debug_log("PKT #%lu: Forwarded to BANK\n", pkt_count);
       }

       // Packet from the bank: forward it to the ATM
       else if(incoming_port == BANK_PORT)
       {
           debug_log("PKT #%lu: BANK -> ATM (%d bytes)\n", pkt_count, n);
           print_hex("Raw packet", (unsigned char*)mesg, n);
           router_sendto_atm(router, mesg, n);
           debug_log("PKT #%lu: Forwarded to ATM\n", pkt_count);
       }

       else
       {
           debug_log("PKT #%lu: UNKNOWN SOURCE (port %d) - DROPPING\n", pkt_count, incoming_port);
           fprintf(stderr, "> I don't know who this came from: dropping it\n");
       }
   }

   return EXIT_SUCCESS;
}
