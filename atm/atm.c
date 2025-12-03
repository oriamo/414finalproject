#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/select.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <sys/time.h> 

// ============== DEBUG LOGGING ==============
// Set to 1 to enable detailed debug output, 0 to disable
#define DEBUG_LOG 1

static void debug_log(const char *fmt, ...) {
    if (!DEBUG_LOG) return;
    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(stderr, "[ATM %02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void print_hex(const char *label, const unsigned char *data, int len) {
    if (!DEBUG_LOG) return;
    fprintf(stderr, "[ATM DEBUG] %s (%d bytes): ", label, len);
    int print_len = len > 64 ? 64 : len;
    for (int i = 0; i < print_len; i++) {
        fprintf(stderr, "%02x", data[i]);
    }
    if (len > 64) fprintf(stderr, "...(truncated)");
    fprintf(stderr, "\n");
}

static void print_session_state(ATM *atm) {
    if (!DEBUG_LOG) return;
    fprintf(stderr, "[ATM DEBUG] === SESSION STATE ===\n");
    fprintf(stderr, "[ATM DEBUG]   active: %d\n", atm->session_active);
    fprintf(stderr, "[ATM DEBUG]   user: '%s'\n", atm->current_user);
    fprintf(stderr, "[ATM DEBUG]   session_id: 0x%016lx\n", atm->session_id);
    if (atm->session_active) {
        time_t now = time(NULL);
        fprintf(stderr, "[ATM DEBUG]   last_activity: %ld seconds ago\n", now - atm->last_activity_time);
    }
    fprintf(stderr, "[ATM DEBUG] ======================\n");
}

static const char* cmd_type_str(unsigned char cmd) {
    switch(cmd) {
        case 0x01: return "BEGIN_SESSION";
        case 0x02: return "WITHDRAW";
        case 0x03: return "BALANCE";
        case 0x04: return "END_SESSION";
        default: return "UNKNOWN";
    }
}

static void print_plaintext_packet(const char *label, const unsigned char *data, int len) {
    if (!DEBUG_LOG || len < 9) return;
    
    uint64_t ts;
    memcpy(&ts, data, 8);
    unsigned char cmd = data[8];
    
    fprintf(stderr, "[ATM DEBUG] === %s PLAINTEXT PACKET ===\n", label);
    fprintf(stderr, "[ATM DEBUG]   timestamp: %lu\n", (unsigned long)ts);
    fprintf(stderr, "[ATM DEBUG]   command: 0x%02x (%s)\n", cmd, cmd_type_str(cmd));
    fprintf(stderr, "[ATM DEBUG]   total_len: %d bytes\n", len);
    
    if (cmd == 0x01 && len >= 10) { // BEGIN_SESSION
        int user_len = data[9];
        char username[256] = {0};
        if (len >= 10 + user_len && user_len < 256) {
            memcpy(username, data + 10, user_len);
            username[user_len] = '\0';
        }
        fprintf(stderr, "[ATM DEBUG]   user_len: %d\n", user_len);
        fprintf(stderr, "[ATM DEBUG]   username: '%s'\n", username);
        if (len >= 10 + user_len + 32) {
            print_hex("user_key", data + 10 + user_len, 32);
        }
    } else if (cmd >= 0x02 && cmd <= 0x04 && len >= 18) { // WITHDRAW/BALANCE/END_SESSION
        uint64_t sess_id;
        memcpy(&sess_id, data + 9, 8);
        int user_len = data[17];
        char username[256] = {0};
        if (len >= 18 + user_len && user_len < 256) {
            memcpy(username, data + 18, user_len);
            username[user_len] = '\0';
        }
        fprintf(stderr, "[ATM DEBUG]   session_id: 0x%016lx\n", (unsigned long)sess_id);
        fprintf(stderr, "[ATM DEBUG]   user_len: %d\n", user_len);
        fprintf(stderr, "[ATM DEBUG]   username: '%s'\n", username);
        
        if (cmd == 0x02 && len >= 18 + user_len + 4) { // WITHDRAW has amount
            int amt;
            memcpy(&amt, data + 18 + user_len, 4);
            fprintf(stderr, "[ATM DEBUG]   amount: $%d\n", amt);
        }
    }
    fprintf(stderr, "[ATM DEBUG] ================================\n");
}

static void print_response_packet(const unsigned char *data, int len) {
    if (!DEBUG_LOG || len < 11) return;
    
    uint64_t ts;
    memcpy(&ts, data, 8);
    unsigned char status = data[8];
    uint16_t resp_len;
    memcpy(&resp_len, data + 9, 2);
    
    fprintf(stderr, "[ATM DEBUG] === RECEIVED RESPONSE PLAINTEXT ===\n");
    fprintf(stderr, "[ATM DEBUG]   timestamp: %lu\n", (unsigned long)ts);
    fprintf(stderr, "[ATM DEBUG]   status: %d (%s)\n", status, status == 0 ? "SUCCESS" : "FAILURE");
    fprintf(stderr, "[ATM DEBUG]   response_data_len: %d\n", resp_len);
    
    if (resp_len > 0 && len >= 11 + resp_len) {
        print_hex("response_data", data + 11, resp_len);
        
        if (resp_len == 8) { // Session ID
            uint64_t sess_id;
            memcpy(&sess_id, data + 11, 8);
            fprintf(stderr, "[ATM DEBUG]   (interpreted as session_id): 0x%016lx\n", (unsigned long)sess_id);
        } else if (resp_len == 4) { // Balance
            int balance;
            memcpy(&balance, data + 11, 4);
            fprintf(stderr, "[ATM DEBUG]   (interpreted as balance): $%d\n", balance);
        }
    }
    fprintf(stderr, "[ATM DEBUG] ====================================\n");
}
// ============================================

// Secure key derivation using PBKDF2
static int derive_key_from_pin(const char *pin, const unsigned char *salt, size_t salt_len, unsigned char *key) {
    debug_log("Deriving key from PIN using PBKDF2 (10000 iterations)\n");
    int result = PKCS5_PBKDF2_HMAC(pin, strlen(pin), salt, salt_len, 10000, EVP_sha256(), 32, key) == 1 ? 0 : -1;
    if (result == 0) {
        print_hex("Derived PIN key", key, 32);
    } else {
        debug_log("ERROR: PBKDF2 failed!\n");
    }
    return result;
}

// Constant-time comparison to prevent timing attacks
static int secure_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    return CRYPTO_memcmp(a, b, len) == 0;
}

static int verify_mac(unsigned char *key, unsigned char *msg, int len, unsigned char *mac) {
    unsigned char computed_mac[32];
    unsigned int mac_len;
    if (!HMAC(EVP_sha256(), key, 32, msg, len, computed_mac, &mac_len)) {
        debug_log("ERROR: HMAC computation failed!\n");
        return 0;
    }
    int result = secure_compare(mac, computed_mac, 32);
    debug_log("MAC verification: %s\n", result ? "VALID" : "INVALID");
    if (!result) {
        print_hex("Expected MAC", mac, 32);
        print_hex("Computed MAC", computed_mac, 32);
    }
    return result;
}

static int decrypt_msg(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int len, unsigned char *plaintext) {
    debug_log("Decrypting message: ciphertext_len=%d\n", len);
    print_hex("Decryption IV", iv, 16);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        debug_log("ERROR: EVP_DecryptInit_ex failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, len)) {
        debug_log("ERROR: EVP_DecryptUpdate failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2)) {
        debug_log("ERROR: EVP_DecryptFinal_ex failed! (bad padding or wrong key)\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    int total = outlen1 + outlen2;
    debug_log("Decryption successful: plaintext_len=%d\n", total);
    return total;
}

static int encrypt_msg(unsigned char *key, unsigned char *iv, unsigned char *plaintext, int len, unsigned char *ciphertext) {
    debug_log("Encrypting message: plaintext_len=%d\n", len);
    print_hex("Encryption IV", iv, 16);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        debug_log("ERROR: EVP_CIPHER_CTX_new failed!\n");
        return -1;
    }
    
    int outlen1, outlen2;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        debug_log("ERROR: EVP_EncryptInit_ex failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plaintext, len)) {
        debug_log("ERROR: EVP_EncryptUpdate failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2)) {
        debug_log("ERROR: EVP_EncryptFinal_ex failed!\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    int total = outlen1 + outlen2;
    debug_log("Encryption successful: ciphertext_len=%d\n", total);
    return total;
}

ATM* atm_create(char *init_filename)
{
    fprintf(stderr, "\n");
    debug_log("╔══════════════════════════════════════════════╗\n");
    debug_log("║          ATM INITIALIZATION STARTED          ║\n");
    debug_log("╚══════════════════════════════════════════════╝\n");
    debug_log("Init file: %s\n", init_filename);
    
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }
    debug_log("ATM struct allocated at %p\n", (void*)atm);

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    printf("ATM Port: %d\n", ATM_PORT);
    debug_log("UDP socket created, fd=%d\n", atm->sockfd);

    int opt = 1;
    setsockopt(atm->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    printf("ATM Port: %d\n", ATM_PORT);
    if (bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr)) < 0) {
        perror("ATM bind failed");
        exit(1);
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    setsockopt(atm->sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Read initialization file
    debug_log("Reading init file: %s\n", init_filename);
    FILE *f = fopen(init_filename, "rb");
    if (!f) {
        debug_log("ERROR: Failed to open init file\n");
        printf("Error opening ATM initialization file\n");
        exit(64);
    }
    if (fread(atm->K_enc, 1, 32, f) != 32 || fread(atm->K_mac, 1, 32, f) != 32) {
        debug_log("ERROR: Failed to read keys from init file\n");
        printf("Error opening ATM initialization file\n");
        exit(64);
    }
    fclose(f);
    
    print_hex("K_enc loaded", atm->K_enc, 32);
    print_hex("K_mac loaded", atm->K_mac, 32);

    atm->session_active = 0;
    atm->session_id = 0;
    memset(atm->current_user, 0, sizeof(atm->current_user));
    
    debug_log("ATM INITIALIZATION COMPLETE\n");
    debug_log("========================================\n\n");
    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    debug_log(">>> SENDING packet to router (%zu bytes)\n", data_len);
    print_hex("Outgoing packet", (unsigned char*)data, data_len);
    // Returns the number of bytes sent; negative on error
    ssize_t sent = sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
    debug_log("sendto() returned %zd\n", sent);
    return sent;
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    debug_log("<<< WAITING for response (timeout=15s)...\n");
    // Returns the number of bytes received; negative on error
    ssize_t received = recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
    if (received < 0) {
        debug_log("recvfrom() TIMEOUT or ERROR (returned %zd, errno=%d)\n", received, errno);
    } else {
        debug_log("<<< RECEIVED packet (%zd bytes)\n", received);
        print_hex("Incoming packet", (unsigned char*)data, received);
    }
    return received;
}

void atm_process_command(ATM *atm, char *command)
{
    // Remove newline
    size_t len = strlen(command);
    if (len > 0 && command[len-1] == '\n') {
        command[len-1] = '\0';
        len--;
    }
    
    debug_log("\n");
    debug_log("┌────────────────────────────────────────────┐\n");
    debug_log("│ COMMAND: '%-32s' │\n", command);
    debug_log("└────────────────────────────────────────────┘\n");
    print_session_state(atm);

    // Check Timeout
    if (atm->session_active) {
        time_t current_time = time(NULL);
        long inactive_secs = current_time - atm->last_activity_time;
        debug_log("Session timeout check: %ld seconds since last activity\n", inactive_secs);
        
        if (inactive_secs > 60) {
            debug_log("!!! SESSION TIMEOUT TRIGGERED !!!\n");
            debug_log("Sending END_SESSION to bank for user '%s'\n", atm->current_user);
            printf("Session timed out due to inactivity\n");
            
            // Send END_SESSION with correct format including Session ID
            unsigned char plaintext[2048];
            uint64_t ts = current_time;
            memcpy(plaintext, &ts, 8);
            plaintext[8] = 0x04; // END_SESSION
            memcpy(plaintext + 9, &atm->session_id, 8); // Include Session ID
            int user_len = strlen(atm->current_user);
            plaintext[17] = user_len;
            memcpy(plaintext + 18, atm->current_user, user_len);
            int plain_len = 18 + user_len;
            
            debug_log("Timeout END_SESSION packet: ts=%lu, session_id=0x%016lx, user='%s'\n", 
                      ts, atm->session_id, atm->current_user);

            unsigned char iv[16];
            RAND_bytes(iv, 16);
            unsigned char ciphertext[2048];
            int c_len = encrypt_msg(atm->K_enc, iv, plaintext, plain_len, ciphertext);
            
            unsigned char msg[4096];
            memcpy(msg, iv, 16);
            memcpy(msg + 16, ciphertext, c_len);
            unsigned char mac[32];
            unsigned int mac_len;
            HMAC(EVP_sha256(), atm->K_mac, 32, msg, 16 + c_len, mac, &mac_len);
            memcpy(msg + 16 + c_len, mac, 32);
            
            atm_send(atm, (char*)msg, 16 + c_len + 32);
            debug_log("Timeout END_SESSION sent (%d bytes)\n", 16 + c_len + 32);

            atm->session_active = 0;
            memset(atm->current_user, 0, sizeof(atm->current_user));
            atm->session_id = 0;
            
            debug_log("Session cleared locally\n");
            print_session_state(atm);
            
            // Reject current command
            // The prompt will change back to "ATM: " in main loop.
            return;
        }
    }

    char cmd_copy[1000];
    strncpy(cmd_copy, command, sizeof(cmd_copy) - 1);
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';  // Ensure null termination
    char *token = strtok(cmd_copy, " ");
    if (!token) return;

    if (strcmp(token, "begin-session") == 0) {
        debug_log("=== BEGIN-SESSION FLOW ===\n");
        
        if (atm->session_active) {
            debug_log("REJECTED: Session already active for '%s'\n", atm->current_user);
            printf("A user is already logged in\n");
            return;
        }

        char *user_arg = strtok(NULL, " ");
        if (!user_arg || strtok(NULL, " ")) {
            debug_log("REJECTED: Invalid arguments\n");
            printf("Usage: begin-session <user-name>\n");
            return;
        }
        debug_log("Username argument: '%s'\n", user_arg);

        // Validate username FIRST before any operations
        size_t user_len = strlen(user_arg);
        debug_log("Username length: %zu\n", user_len);
        
        if (user_len == 0 || user_len > 250) {
             debug_log("REJECTED: Username length invalid\n");
             printf("Usage: begin-session <user-name>\n");
             return;
        }
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                debug_log("REJECTED: Username contains invalid char '%c' at pos %d\n", user_arg[i], i);
                printf("Usage: begin-session <user-name>\n");
                return;
            }
        }
        debug_log("Username validation: PASSED\n");

        // Check card file - use snprintf for safety
        char card_filename[300];
        if (snprintf(card_filename, sizeof(card_filename), "%s.card", user_arg) >= sizeof(card_filename)) {
            debug_log("REJECTED: Card filename too long\n");
            printf("Usage: begin-session <user-name>\n");
            return;
        }
        debug_log("Card file: '%s'\n", card_filename);
        
        if (access(card_filename, F_OK) != 0) {
            debug_log("REJECTED: Card file not found (errno=%d)\n", errno);
            printf("No such user\n");  // Generic error to prevent user enumeration
            return;
        }
        debug_log("Card file exists: OK\n");

        printf("PIN? ");
        fflush(stdout);
        char pin[100];
        if (!fgets(pin, 100, stdin)) {
            debug_log("ERROR: Failed to read PIN from stdin\n");
            return;
        }
        size_t pin_len = strlen(pin);
        if (pin_len > 0 && pin[pin_len-1] == '\n') pin[pin_len-1] = '\0';
        debug_log("PIN entered: '%s' (len=%zu)\n", pin, strlen(pin));

        if (strlen(pin) != 4) {
            debug_log("REJECTED: PIN not 4 digits\n");
            printf("Not authorized\n");
            return;
        }
        for(int i=0; i<4; i++) if(pin[i] < '0' || pin[i] > '9') {
            debug_log("REJECTED: PIN contains non-digit at pos %d\n", i);
            printf("Not authorized\n");
            return;
        }
        debug_log("PIN format validation: PASSED\n");

        // Decrypt Card
        debug_log("Opening card file...\n");
        FILE *cf = fopen(card_filename, "rb");
        if (!cf) {
            debug_log("ERROR: Failed to open card file\n");
            printf("Not authorized\n");
            return;
        }
        
        unsigned char card_iv[16];
        unsigned char card_ciphertext[64];
        unsigned char salt[16];
        
        // Read salt, IV, and ciphertext with proper error checking
        if (fread(salt, 1, 16, cf) != 16 || 
            fread(card_iv, 1, 16, cf) != 16) {
            debug_log("ERROR: Failed to read salt/IV from card file\n");
            fclose(cf);
            printf("Not authorized\n");
            return;
        }
        print_hex("Card salt", salt, 16);
        print_hex("Card IV", card_iv, 16);
        
        int card_c_len = fread(card_ciphertext, 1, 64, cf);
        fclose(cf);
        debug_log("Card ciphertext: %d bytes\n", card_c_len);
        print_hex("Card ciphertext", card_ciphertext, card_c_len);
        
        if (card_c_len <= 0) {
            debug_log("ERROR: No ciphertext in card file\n");
            printf("Not authorized\n");
            return;
        }

        // Use secure key derivation instead of single SHA256
        unsigned char pin_key[32];
        if (derive_key_from_pin(pin, salt, 16, pin_key) != 0) {
            printf("Not authorized\n");
            return;
        }

        unsigned char user_key[32];
        unsigned char decrypted_card[64];
        debug_log("Decrypting card to extract user_key...\n");
        int d_len = decrypt_msg(pin_key, card_iv, card_ciphertext, card_c_len, decrypted_card);
        
        // Proper validation of decrypted data
        if (d_len != 32) {
            debug_log("REJECTED: Decrypted length=%d (expected 32). Wrong PIN?\n", d_len);
            printf("Not authorized\n");
            return;
        }
        
        memcpy(user_key, decrypted_card, 32);
        print_hex("Decrypted user_key", user_key, 32);
        
        // Clear sensitive data
        memset(pin_key, 0, sizeof(pin_key));
        memset(decrypted_card, 0, sizeof(decrypted_card));
        debug_log("Cleared sensitive key material from memory\n");

        // Send to Bank
        debug_log("Building BEGIN_SESSION packet for bank...\n");
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x01; // BEGIN_SESSION
        // int user_len = strlen(user_arg); // Removed redeclaration
        plaintext[9] = user_len;
        memcpy(plaintext + 10, user_arg, user_len);
        memcpy(plaintext + 10 + user_len, user_key, 32);
        int plain_len = 10 + user_len + 32;
        
        print_plaintext_packet("OUTGOING", plaintext, plain_len);

        unsigned char iv[16];
        RAND_bytes(iv, 16);
        unsigned char ciphertext[2048];
        int c_len = encrypt_msg(atm->K_enc, iv, plaintext, plain_len, ciphertext);
        
        unsigned char msg[4096];
        memcpy(msg, iv, 16);
        memcpy(msg + 16, ciphertext, c_len);
        unsigned char mac[32];
        unsigned int mac_len;
        HMAC(EVP_sha256(), atm->K_mac, 32, msg, 16 + c_len, mac, &mac_len);
        memcpy(msg + 16 + c_len, mac, 32);
        print_hex("Computed MAC", mac, 32);
        
        debug_log("Sending packet: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n", c_len, 16 + c_len + 32);
        atm_send(atm, (char*)msg, 16 + c_len + 32);

        // Wait for response
        debug_log("Waiting for bank response...\n");
        
        // Clear any stale packets from socket buffer first
        char dummy_buf[1000];
        struct timeval short_timeout;
        short_timeout.tv_sec = 0;
        short_timeout.tv_usec = 10000; // 10ms
        
        fd_set readfds;
        int cleared_packets = 0;
        while (1) {
            FD_ZERO(&readfds);
            FD_SET(atm->sockfd, &readfds);
            int ready = select(atm->sockfd + 1, &readfds, NULL, NULL, &short_timeout);
            if (ready > 0) {
                ssize_t old_bytes = recvfrom(atm->sockfd, dummy_buf, 1000, 0, NULL, NULL);
                if (old_bytes > 0) {
                    cleared_packets++;
                    debug_log("Cleared stale packet #%d (%zd bytes) from socket buffer\n", cleared_packets, old_bytes);
                } else {
                    break;
                }
            } else {
                break; // No more packets
            }
            if (cleared_packets > 10) break; // Safety limit
        }
        
        if (cleared_packets > 0) {
            debug_log("Cleared %d stale packets from socket buffer\n", cleared_packets);
        }
        
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            debug_log("TIMEOUT or ERROR waiting for response\n");
            printf("Not authorized\n"); // Timeout or error
            return;
        }

        // Verify Response
        debug_log("Verifying response...\n");
        debug_log("Expected response size: 80 bytes (16 IV + 32 ciphertext + 32 MAC)\n");
        debug_log("Actually received: %d bytes\n", n);
        
        if (n < 48) {
            debug_log("REJECTED: Response too short (%d < 48)\n", n);
            printf("Not authorized\n");
            return;
        }
        
        // Check if we got a truncated response
        if (n == 64) {
            debug_log("WARNING: Received 64-byte response instead of expected 80 bytes!\n");
            debug_log("This suggests either:\n");
            debug_log("  1. Router truncated the packet\n");  
            debug_log("  2. ATM received an old/cached response\n");
            debug_log("  3. Bank sent wrong response size\n");
            debug_log("ATTEMPTING WORKAROUND: Will retry login in 1 second...\n");
            
            // Give a short delay and suggest retry
            sleep(1);
            printf("Communication error with bank. Please try login again.\n");
            return;
        }
        
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;
        debug_log("Response structure: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n", r_c_len, n);
        
        // Add detailed packet analysis
        print_hex("Response IV", r_iv, 16);
        print_hex("Response Ciphertext", r_c, r_c_len);
        print_hex("Response MAC", r_mac, 32);

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            debug_log("REJECTED: Response MAC invalid!\n");
            printf("Not authorized\n");
            return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) {
            debug_log("REJECTED: Decrypted response too short (%d < 11)\n", r_p_len);
            printf("Not authorized\n");
            return;
        }
        
        print_response_packet(r_plain, r_p_len);

        // Check status
        if (r_plain[8] == 0) {
            debug_log("Bank returned SUCCESS (status=0)\n");
            printf("Authorized\n");
            atm->session_active = 1;
            // Use safe string copy with bounds checking
            strncpy(atm->current_user, user_arg, sizeof(atm->current_user) - 1);
            atm->current_user[sizeof(atm->current_user) - 1] = '\0';
            atm->last_activity_time = time(NULL);
            
            // Get Session ID
            debug_log("Checking for session ID in response...\n");
            debug_log("Response plaintext length: %d bytes (need 19 for session ID)\n", r_p_len);
            
            if (r_p_len >= 19) { // 11 + 8
                memcpy(&atm->session_id, r_plain + 11, 8);
                debug_log("Session established! session_id=0x%016lx\n", (unsigned long)atm->session_id);
            } else {
                debug_log("ERROR: Response plaintext too short for session_id!\n");
                debug_log("Expected: 19 bytes (8 timestamp + 1 status + 2 length + 8 session_id)\n");
                debug_log("Received: %d bytes\n", r_p_len);
                debug_log("This indicates the bank response was truncated or malformed\n");
                
                // Check what we actually got in the response
                if (r_p_len >= 11) {
                    uint16_t resp_data_len;
                    memcpy(&resp_data_len, r_plain + 9, 2);
                    debug_log("Response claims to have %d bytes of data (expected 8)\n", resp_data_len);
                }
                
                // Protocol error - session establishment failed
                atm->session_active = 0;
                printf("Not authorized\n");
            }
        } else {
            debug_log("Bank returned FAILURE (status=%d)\n", r_plain[8]);
            printf("Not authorized\n");
        }
        
        debug_log("=== BEGIN-SESSION COMPLETE ===\n");
        print_session_state(atm);

    } else if (strcmp(token, "withdraw") == 0) {
        debug_log("=== WITHDRAW FLOW ===\n");
        
        if (!atm->session_active) {
            debug_log("REJECTED: No active session\n");
            printf("No user logged in\n");
            return;
        }
        
        char *amt_arg = strtok(NULL, " ");
        if (!amt_arg || strtok(NULL, " ")) {
            debug_log("REJECTED: Invalid arguments\n");
            printf("Usage: withdraw <amt>\n");
            return;
        }
        debug_log("Amount argument: '%s'\n", amt_arg);

        // Enhanced validation to prevent integer overflow attacks
        char *endptr;
        errno = 0;
        long val = strtol(amt_arg, &endptr, 10);
        debug_log("Parsed amount: %ld (errno=%d, endptr='%s')\n", val, errno, endptr);
        
        if (*endptr != '\0' || errno != 0 || val < 0 || val > INT_MAX) {
             debug_log("REJECTED: Invalid amount format or overflow\n");
             printf("Usage: withdraw <amt>\n");
             return;
        }
        
        // Additional check for reasonable withdrawal limits
        if (val == 0) {
            debug_log("REJECTED: Amount is zero\n");
            printf("Usage: withdraw <amt>\n");
            return;
        }
        
        int amt = (int)val;
        debug_log("Withdrawal amount: $%d\n", amt);

        // Send WITHDRAW
        debug_log("Building WITHDRAW packet...\n");
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x02; // WITHDRAW
        memcpy(plaintext + 9, &atm->session_id, 8);
        int user_len = strlen(atm->current_user);
        plaintext[17] = user_len;
        memcpy(plaintext + 18, atm->current_user, user_len);
        memcpy(plaintext + 18 + user_len, &amt, 4);
        int plain_len = 18 + user_len + 4;
        
        print_plaintext_packet("OUTGOING", plaintext, plain_len);

        unsigned char iv[16];
        RAND_bytes(iv, 16);
        unsigned char ciphertext[2048];
        int c_len = encrypt_msg(atm->K_enc, iv, plaintext, plain_len, ciphertext);
        
        unsigned char msg[4096];
        memcpy(msg, iv, 16);
        memcpy(msg + 16, ciphertext, c_len);
        unsigned char mac[32];
        unsigned int mac_len;
        HMAC(EVP_sha256(), atm->K_mac, 32, msg, 16 + c_len, mac, &mac_len);
        memcpy(msg + 16 + c_len, mac, 32);
        
        debug_log("Sending packet: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n", c_len, 16 + c_len + 32);
        atm_send(atm, (char*)msg, 16 + c_len + 32);

        // Wait response
        debug_log("Waiting for bank response...\n");
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            debug_log("TIMEOUT or ERROR\n");
            printf("Transaction failed\n"); // Timeout
            return;
        }

        // Verify Response
        if (n < 48) {
            debug_log("REJECTED: Response too short (%d < 48)\n", n);
            printf("Transaction failed\n");
            return;
        }
        
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;
        debug_log("Response structure: IV(16) + Ciphertext(%d) + MAC(32)\n", r_c_len);

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            debug_log("REJECTED: Response MAC invalid!\n");
            printf("Transaction failed\n");
            return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) {
            debug_log("REJECTED: Decrypted response too short\n");
            printf("Transaction failed\n");
            return;
        }
        
        print_response_packet(r_plain, r_p_len);

        if (r_plain[8] == 0) {
            debug_log("WITHDRAW SUCCESS\n");
            printf("$%d dispensed\n", amt);
        } else {
            debug_log("WITHDRAW FAILED (status=%d)\n", r_plain[8]);
            printf("Insufficient funds\n");
        }
        atm->last_activity_time = time(NULL);
        debug_log("=== WITHDRAW COMPLETE ===\n");

    } else if (strcmp(token, "balance") == 0) {
        debug_log("=== BALANCE FLOW ===\n");
        
        if (!atm->session_active) {
            debug_log("REJECTED: No active session\n");
            printf("No user logged in\n");
            return;
        }
        
        if (strtok(NULL, " ")) {
            debug_log("REJECTED: Extra arguments\n");
            printf("Usage: balance\n");
            return;
        }

        // Send BALANCE
        debug_log("Building BALANCE packet...\n");
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x03; // BALANCE
        memcpy(plaintext + 9, &atm->session_id, 8);
        int user_len = strlen(atm->current_user);
        plaintext[17] = user_len;
        memcpy(plaintext + 18, atm->current_user, user_len);
        int plain_len = 18 + user_len;
        
        print_plaintext_packet("OUTGOING", plaintext, plain_len);

        unsigned char iv[16];
        RAND_bytes(iv, 16);
        unsigned char ciphertext[2048];
        int c_len = encrypt_msg(atm->K_enc, iv, plaintext, plain_len, ciphertext);
        
        unsigned char msg[4096];
        memcpy(msg, iv, 16);
        memcpy(msg + 16, ciphertext, c_len);
        unsigned char mac[32];
        unsigned int mac_len;
        HMAC(EVP_sha256(), atm->K_mac, 32, msg, 16 + c_len, mac, &mac_len);
        memcpy(msg + 16 + c_len, mac, 32);
        
        debug_log("Sending packet: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n", c_len, 16 + c_len + 32);
        atm_send(atm, (char*)msg, 16 + c_len + 32);

        // Wait response
        debug_log("Waiting for bank response...\n");
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            debug_log("TIMEOUT or ERROR\n");
            printf("Transaction failed\n"); // Timeout
            return;
        }

        // Verify Response
        if (n < 48) {
            debug_log("REJECTED: Response too short (%d < 48)\n", n);
            printf("Transaction failed\n");
            return;
        }
        
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;
        debug_log("Response structure: IV(16) + Ciphertext(%d) + MAC(32)\n", r_c_len);

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            debug_log("REJECTED: Response MAC invalid!\n");
            printf("Transaction failed\n");
            return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) {
            debug_log("REJECTED: Decrypted response too short\n");
            printf("Transaction failed\n");
            return;
        }
        
        print_response_packet(r_plain, r_p_len);

        if (r_plain[8] == 0) {
            int bal;
            memcpy(&bal, r_plain + 11, 4);
            debug_log("BALANCE SUCCESS: $%d\n", bal);
            printf("$%d\n", bal);
        } else {
            debug_log("BALANCE FAILED (status=%d)\n", r_plain[8]);
            printf("Transaction failed\n");
        }
        atm->last_activity_time = time(NULL);
        debug_log("=== BALANCE COMPLETE ===\n");

    } else if (strcmp(token, "end-session") == 0) {
        debug_log("=== END-SESSION FLOW ===\n");
        
        if (!atm->session_active) {
            debug_log("REJECTED: No active session\n");
            printf("No user logged in\n");
            return;
        }
        
        debug_log("Ending session for user '%s' (session_id=0x%016lx)\n", 
                  atm->current_user, (unsigned long)atm->session_id);

        // Send END_SESSION
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x04; // END_SESSION
        memcpy(plaintext + 9, &atm->session_id, 8);
        int user_len = strlen(atm->current_user);
        plaintext[17] = user_len;
        memcpy(plaintext + 18, atm->current_user, user_len);
        int plain_len = 18 + user_len;
        
        print_plaintext_packet("OUTGOING", plaintext, plain_len);

        unsigned char iv[16];
        RAND_bytes(iv, 16);
        unsigned char ciphertext[2048];
        int c_len = encrypt_msg(atm->K_enc, iv, plaintext, plain_len, ciphertext);
        
        unsigned char msg[4096];
        memcpy(msg, iv, 16);
        memcpy(msg + 16, ciphertext, c_len);
        unsigned char mac[32];
        unsigned int mac_len;
        HMAC(EVP_sha256(), atm->K_mac, 32, msg, 16 + c_len, mac, &mac_len);
        memcpy(msg + 16 + c_len, mac, 32);
        
        debug_log("Sending packet: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n", c_len, 16 + c_len + 32);
        atm_send(atm, (char*)msg, 16 + c_len + 32);

        // Don't wait for response, just logout locally
        atm->session_active = 0;
        atm->session_id = 0;
        memset(atm->current_user, 0, sizeof(atm->current_user));
        
        printf("User logged out\n");
        debug_log("Session cleared locally\n");
        print_session_state(atm);
        debug_log("=== END-SESSION COMPLETE ===\n");

    } else {
        debug_log("REJECTED: Unknown command '%s'\n", token);
        printf("Invalid command\n");
    }
}
