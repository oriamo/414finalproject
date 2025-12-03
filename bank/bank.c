#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <time.h>

// ============== DEBUG LOGGING ==============
// Set to 1 to enable detailed debug output, 0 to disable
#define DEBUG_LOG 1

static void debug_log(const char *fmt, ...) {
    if (!DEBUG_LOG) return;
    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(stderr, "[BANK %02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

static void print_hex(const char *label, const unsigned char *data, int len) {
    if (!DEBUG_LOG) return;
    fprintf(stderr, "[BANK DEBUG] %s (%d bytes): ", label, len);
    int print_len = len > 64 ? 64 : len;
    for (int i = 0; i < print_len; i++) {
        fprintf(stderr, "%02x", data[i]);
    }
    if (len > 64) fprintf(stderr, "...(truncated)");
    fprintf(stderr, "\n");
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

static void print_decrypted_packet(const unsigned char *data, int len) {
    if (!DEBUG_LOG || len < 9) return;
    
    uint64_t ts;
    memcpy(&ts, data, 8);
    unsigned char cmd = data[8];
    
    fprintf(stderr, "[BANK DEBUG] === DECRYPTED REQUEST PACKET ===\n");
    fprintf(stderr, "[BANK DEBUG]   timestamp: %lu\n", (unsigned long)ts);
    fprintf(stderr, "[BANK DEBUG]   command: 0x%02x (%s)\n", cmd, cmd_type_str(cmd));
    fprintf(stderr, "[BANK DEBUG]   total_len: %d bytes\n", len);
    
    if (cmd == 0x01 && len >= 10) { // BEGIN_SESSION
        int user_len = data[9];
        char username[256] = {0};
        if (len >= 10 + user_len) {
            memcpy(username, data + 10, user_len);
            username[user_len] = '\0';
        }
        fprintf(stderr, "[BANK DEBUG]   user_len: %d\n", user_len);
        fprintf(stderr, "[BANK DEBUG]   username: '%s'\n", username);
        if (len >= 10 + user_len + 32) {
            print_hex("user_key", data + 10 + user_len, 32);
        }
    } else if (cmd >= 0x02 && cmd <= 0x04 && len >= 18) { // WITHDRAW/BALANCE/END_SESSION
        uint64_t sess_id;
        memcpy(&sess_id, data + 9, 8);
        int user_len = data[17];
        char username[256] = {0};
        if (len >= 18 + user_len) {
            memcpy(username, data + 18, user_len);
            username[user_len] = '\0';
        }
        fprintf(stderr, "[BANK DEBUG]   session_id: 0x%016lx\n", (unsigned long)sess_id);
        fprintf(stderr, "[BANK DEBUG]   user_len: %d\n", user_len);
        fprintf(stderr, "[BANK DEBUG]   username: '%s'\n", username);
        
        if (cmd == 0x02 && len >= 18 + user_len + 4) { // WITHDRAW has amount
            int amt;
            memcpy(&amt, data + 18 + user_len, 4);
            fprintf(stderr, "[BANK DEBUG]   amount: $%d\n", amt);
        }
    }
    fprintf(stderr, "[BANK DEBUG] ================================\n");
}

static void print_response_packet(unsigned char status, int response_len, const unsigned char *response_data) {
    if (!DEBUG_LOG) return;
    
    fprintf(stderr, "[BANK DEBUG] === RESPONSE PACKET ===\n");
    fprintf(stderr, "[BANK DEBUG]   status: %d (%s)\n", status, status == 0 ? "SUCCESS" : "FAILURE");
    fprintf(stderr, "[BANK DEBUG]   response_data_len: %d\n", response_len);
    
    if (response_len > 0) {
        print_hex("response_data", response_data, response_len);
        
        if (response_len == 8) { // Session ID
            uint64_t sess_id;
            memcpy(&sess_id, response_data, 8);
            fprintf(stderr, "[BANK DEBUG]   (interpreted as session_id): 0x%016lx\n", (unsigned long)sess_id);
        } else if (response_len == 4) { // Balance
            int balance;
            memcpy(&balance, response_data, 4);
            fprintf(stderr, "[BANK DEBUG]   (interpreted as balance): $%d\n", balance);
        }
    }
    fprintf(stderr, "[BANK DEBUG] ========================\n");
}
// ============================================

typedef struct _User {
    char username[251];
    unsigned char user_key[32];
    int balance;
} User;

typedef struct _SessionData {
    uint64_t session_id;
    time_t last_active;
} SessionData;

Bank* bank_create(char *init_filename)
{
    fprintf(stderr, "\n");
    debug_log("╔══════════════════════════════════════════════╗\n");
    debug_log("║          BANK INITIALIZATION STARTED         ║\n");
    debug_log("╚══════════════════════════════════════════════╝\n");
    debug_log("Init file: %s\n", init_filename);
    
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }
    debug_log("Bank struct allocated at %p\n", (void*)bank);

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);
    debug_log("UDP socket created, fd=%d\n", bank->sockfd);

    int opt = 1;
    setsockopt(bank->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);
    debug_log("Router address configured: 127.0.0.1:%d\n", ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    if (bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr)) < 0) {
        debug_log("ERROR: bind() failed!\n");
        perror("Bank bind failed");
        exit(1);
    }
    debug_log("Socket bound to 127.0.0.1:%d\n", BANK_PORT);

    // Read initialization file
    debug_log("Opening init file: %s\n", init_filename);
    FILE *f = fopen(init_filename, "rb");
    if (!f) {
        debug_log("ERROR: Failed to open init file '%s'\n", init_filename);
        printf("Error opening bank initialization file\n");
        exit(64);
    }
    if (fread(bank->K_enc, 1, 32, f) != 32 || fread(bank->K_mac, 1, 32, f) != 32) {
        debug_log("ERROR: Failed to read 64 bytes from init file\n");
        printf("Error opening bank initialization file\n");
        exit(64);
    }
    fclose(f);
    debug_log("Successfully read 64 bytes of key material\n");
    
    print_hex("K_enc (encryption key)", bank->K_enc, 32);
    print_hex("K_mac (MAC key)", bank->K_mac, 32);
    

    // Initialize HashTables
    bank->users = hash_table_create(100);
    bank->active_sessions = hash_table_create(100);
    bank->recent_messages = hash_table_create(1000);
    bank->replay_cleanup_list = list_create();
    debug_log("Hash tables and lists initialized\n");
    debug_log("  users table: %p\n", (void*)bank->users);
    debug_log("  active_sessions table: %p\n", (void*)bank->active_sessions);
    debug_log("  recent_messages table: %p\n", (void*)bank->recent_messages);
    debug_log("  replay_cleanup_list: %p\n", (void*)bank->replay_cleanup_list);

    debug_log("╔══════════════════════════════════════════════╗\n");
    debug_log("║        BANK INITIALIZATION COMPLETE          ║\n");
    debug_log("╚══════════════════════════════════════════════╝\n\n");
    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        debug_log("Freeing Bank resources\n");
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    debug_log(">>> SENDING response to router (%zu bytes)\n", data_len);
    print_hex("Outgoing packet", (unsigned char*)data, data_len);
    // Returns the number of bytes sent; negative on error
    ssize_t sent = sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
    debug_log("sendto() returned %zd\n", sent);
    return sent;
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // Remove newline
    if (len > 0 && command[len-1] == '\n') {
        command[len-1] = '\0';
        len--;
    }

    debug_log("\n");
    debug_log("┌────────────────────────────────────────────┐\n");
    debug_log("│ LOCAL COMMAND: '%-24s' │\n", command);
    debug_log("└────────────────────────────────────────────┘\n");

    // Parse command
    char *token = strtok(command, " ");
    if (!token) {
        debug_log("Empty command, ignoring\n");
        return;
    }
    
    debug_log("Parsed command token: '%s'\n", token);

    if (strcmp(token, "create-user") == 0) {
        debug_log("=== CREATE-USER FLOW ===\n");
        
        char *user_arg = strtok(NULL, " ");
        char *pin_arg = strtok(NULL, " ");
        char *bal_arg = strtok(NULL, " ");
        
        if (!user_arg || !pin_arg || !bal_arg || strtok(NULL, " ")) {
            debug_log("REJECTED: Invalid arguments\n");
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        
        debug_log("Arguments: user='%s', pin='%s', balance='%s'\n", user_arg, pin_arg, bal_arg);
        
        // Validate username
        if (strlen(user_arg) > 250) {
             debug_log("REJECTED: Username too long (>250)\n");
             printf("Usage:  create-user <user-name> <pin> <balance>\n");
             return;
        }
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                debug_log("REJECTED: Username contains invalid char '%c'\n", user_arg[i]);
                printf("Usage:  create-user <user-name> <pin> <balance>\n");
                return;
            }
        }
        debug_log("Username validation: PASSED\n");

        // Validate PIN
        if (strlen(pin_arg) != 4) {
            debug_log("REJECTED: PIN not 4 chars\n");
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        for (int i=0; i<4; i++) {
            if (pin_arg[i] < '0' || pin_arg[i] > '9') {
                debug_log("REJECTED: PIN contains non-digit at position %d\n", i);
                printf("Usage:  create-user <user-name> <pin> <balance>\n");
                return;
            }
        }
        debug_log("PIN validation: PASSED\n");

        // Validate Balance
        char *endptr;
        long val = strtol(bal_arg, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 2147483647) {
             debug_log("REJECTED: Balance invalid or overflow\n");
             printf("Usage:  create-user <user-name> <pin> <balance>\n");
             return;
        }
        int balance = (int)val;
        debug_log("Balance validation: PASSED (balance=$%d)\n", balance);

        // Check if user exists
        if (hash_table_find(bank->users, user_arg)) {
            debug_log("REJECTED: User '%s' already exists\n", user_arg);
            printf("Error:  user %s already exists\n", user_arg);
            return;
        }
        debug_log("User existence check: PASSED (new user)\n");

        // Create user
        User *new_user = malloc(sizeof(User));
        strcpy(new_user->username, user_arg);
        new_user->balance = balance;
        RAND_bytes(new_user->user_key, 32);
        
        debug_log("Created user struct:\n");
        debug_log("  username: '%s'\n", new_user->username);
        debug_log("  balance: $%d\n", new_user->balance);
        print_hex("user_key", new_user->user_key, 32);

        // Create card file
        unsigned char salt[16];
        RAND_bytes(salt, 16);
        print_hex("Card salt", salt, 16);

        unsigned char pin_key[32];
        debug_log("Deriving PIN key using PBKDF2 (10000 iterations)...\n");
        if (PKCS5_PBKDF2_HMAC(pin_arg, strlen(pin_arg), salt, 16, 10000, EVP_sha256(), 32, pin_key) != 1) {
             debug_log("ERROR: PBKDF2 key derivation failed!\n");
             printf("Error deriving key\n");
             return;
        }
        print_hex("Derived PIN key", pin_key, 32);

        unsigned char iv[16];
        RAND_bytes(iv, 16);
        print_hex("Card IV", iv, 16);

        unsigned char ciphertext[64]; 
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outlen1, outlen2;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin_key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &outlen1, new_user->user_key, 32);
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
        EVP_CIPHER_CTX_free(ctx);
        
        debug_log("Encrypted user_key: outlen1=%d, outlen2=%d, total=%d\n", outlen1, outlen2, outlen1+outlen2);
        print_hex("Encrypted user_key ciphertext", ciphertext, outlen1+outlen2);

        char card_filename[300];
        sprintf(card_filename, "%s.card", user_arg);
        debug_log("Creating card file: '%s'\n", card_filename);
        
        FILE *card_file = fopen(card_filename, "wb");
        if (!card_file) {
            debug_log("ERROR: Failed to create card file\n");
            printf("Error creating card file for user %s\n", user_arg);
            free(new_user);
            return;
        }
        fwrite(salt, 1, 16, card_file);
        fwrite(iv, 1, 16, card_file);
        fwrite(ciphertext, 1, outlen1 + outlen2, card_file);
        fclose(card_file);
        debug_log("Card file written: 16 (salt) + 16 (iv) + %d (ciphertext) = %d bytes\n", 
                  outlen1+outlen2, 32 + outlen1 + outlen2);

        hash_table_add(bank->users, new_user->username, new_user);
        debug_log("User added to users hash table\n");
        printf("Created user %s\n", user_arg);
        debug_log("=== CREATE-USER COMPLETE ===\n");

    } else if (strcmp(token, "deposit") == 0) {
        debug_log("=== DEPOSIT FLOW ===\n");
        
        char *user_arg = strtok(NULL, " ");
        char *amt_arg = strtok(NULL, " ");
        
        if (!user_arg || !amt_arg || strtok(NULL, " ")) {
            debug_log("REJECTED: Invalid arguments\n");
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }
        
        debug_log("Arguments: user='%s', amount='%s'\n", user_arg, amt_arg);

        // Validate username chars
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                debug_log("REJECTED: Username contains invalid char '%c'\n", user_arg[i]);
                printf("Usage:  deposit <user-name> <amt>\n");
                return;
            }
        }

        // Validate Amount
        char *endptr;
        long val = strtol(amt_arg, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 2147483647) {
             debug_log("REJECTED: Amount invalid or overflow\n");
             printf("Usage:  deposit <user-name> <amt>\n");
             return;
        }
        int amt = (int)val;
        debug_log("Amount validation: PASSED ($%d)\n", amt);

        User *u = hash_table_find(bank->users, user_arg);
        if (!u) {
            debug_log("REJECTED: User '%s' not found\n", user_arg);
            printf("No such user\n");
            return;
        }
        debug_log("User found: '%s', current balance=$%d\n", u->username, u->balance);

        if ((long)u->balance + amt > 2147483647) {
            debug_log("REJECTED: Deposit would overflow balance\n");
            printf("Too rich for this program\n");
            return;
        }

        u->balance += amt;
        debug_log("New balance: $%d\n", u->balance);
        printf("$%d added to %s's account\n", amt, user_arg);
        debug_log("=== DEPOSIT COMPLETE ===\n");

    } else if (strcmp(token, "balance") == 0) {
        debug_log("=== BALANCE QUERY FLOW ===\n");
        
        char *user_arg = strtok(NULL, " ");
        
        if (!user_arg || strtok(NULL, " ")) {
            debug_log("REJECTED: Invalid arguments\n");
            printf("Usage:  balance <user-name>\n");
            return;
        }
        
        debug_log("Query for user: '%s'\n", user_arg);

        // Validate username chars
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                debug_log("REJECTED: Username contains invalid char '%c'\n", user_arg[i]);
                printf("Usage:  balance <user-name>\n");
                return;
            }
        }

        User *u = hash_table_find(bank->users, user_arg);
        if (!u) {
            debug_log("REJECTED: User '%s' not found\n", user_arg);
            printf("No such user\n");
            return;
        }

        debug_log("User found: '%s', balance=$%d\n", u->username, u->balance);
        printf("$%d\n", u->balance);
        debug_log("=== BALANCE QUERY COMPLETE ===\n");

    } else {
        debug_log("REJECTED: Unknown command '%s'\n", token);
        printf("Invalid command\n");
    }
}

#include <time.h>

static int verify_mac(unsigned char *key, unsigned char *msg, int len, unsigned char *mac) {
    unsigned char computed_mac[32];
    unsigned int mac_len;
    HMAC(EVP_sha256(), key, 32, msg, len, computed_mac, &mac_len);
    int result = CRYPTO_memcmp(mac, computed_mac, 32) == 0;
    debug_log("MAC verification: %s\n", result ? "VALID" : "INVALID");
    if (!result) {
        print_hex("Expected MAC", mac, 32);
        print_hex("Computed MAC", computed_mac, 32);
    }
    return result;
}

static int decrypt_msg(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int len, unsigned char *plaintext) {
    debug_log("Decrypting message: ciphertext_len=%d\n", len);
    print_hex("IV", iv, 16);
    
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
    debug_log("Encrypting response: plaintext_len=%d\n", len);
    print_hex("Response IV", iv, 16);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    int total = outlen1 + outlen2;
    debug_log("Encryption successful: ciphertext_len=%d\n", total);
    return total;
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    debug_log("\n");
    debug_log("┌────────────────────────────────────────────────────┐\n");
    debug_log("│        REMOTE COMMAND RECEIVED (%4zu bytes)        │\n", len);
    debug_log("└────────────────────────────────────────────────────┘\n");
    
    print_hex("Raw incoming packet", (unsigned char*)command, len);
    
    if (len < 48) {
        debug_log("DROPPED: Packet too short (%zu < 48 min for IV+MAC)\n", len);
        return;
    }

    unsigned char *iv = (unsigned char*)command;
    unsigned char *ciphertext = (unsigned char*)command + 16;
    unsigned char *mac = (unsigned char*)command + len - 32;
    int ciphertext_len = len - 48;
    
    debug_log("Packet structure:\n");
    debug_log("  IV: bytes 0-15 (16 bytes)\n");
    debug_log("  Ciphertext: bytes 16-%zu (%d bytes)\n", 16 + ciphertext_len - 1, ciphertext_len);
    debug_log("  MAC: bytes %zu-%zu (32 bytes)\n", len - 32, len - 1);
    
    print_hex("IV", iv, 16);
    print_hex("MAC", mac, 32);

    // Verify MAC
    debug_log("Verifying MAC...\n");
    if (!verify_mac(bank->K_mac, (unsigned char*)command, len - 32, mac)) {
        debug_log("DROPPED: Invalid MAC!\n");
        return;
    }

    // Decrypt
    debug_log("Decrypting ciphertext...\n");
    unsigned char plaintext[2048];
    int plaintext_len = decrypt_msg(bank->K_enc, iv, ciphertext, ciphertext_len, plaintext);
    if (plaintext_len < 0) {
        debug_log("DROPPED: Decryption failed!\n");
        return;
    }
    
    print_hex("Decrypted plaintext", plaintext, plaintext_len);
    print_decrypted_packet(plaintext, plaintext_len);

    // Parse Plaintext
    if (plaintext_len < 9) {
        debug_log("DROPPED: Plaintext too short (%d < 9 min for timestamp+cmd)\n", plaintext_len);
        return;
    }

    uint64_t timestamp;
    memcpy(&timestamp, plaintext, 8);
    unsigned char cmd_type = plaintext[8];
    unsigned char *data = plaintext + 9;
    int data_len = plaintext_len - 9;
    
    debug_log("Parsed header:\n");
    debug_log("  timestamp: %lu\n", (unsigned long)timestamp);
    debug_log("  cmd_type: 0x%02x (%s)\n", cmd_type, cmd_type_str(cmd_type));
    debug_log("  data_len: %d bytes\n", data_len);

    // Check Timestamp
    time_t current_time = time(NULL);
    debug_log("Timestamp validation:\n");
    debug_log("  current_time: %ld\n", (long)current_time);
    debug_log("  packet_time: %lu\n", (unsigned long)timestamp);
    debug_log("  age: %ld seconds\n", (long)(current_time - timestamp));
    
    // Allow 60 seconds window. Also allow small future skew (5s)
    if (current_time > timestamp + 60) {
        debug_log("DROPPED: Packet too old (>60s)\n");
        return;
    }
    if (timestamp > current_time + 5) {
        debug_log("DROPPED: Packet from future (>5s ahead)\n");
        return;
    }
    debug_log("Timestamp validation: PASSED\n");

    // Check Replay Cache
    debug_log("Checking replay cache...\n");
    unsigned char hash[32];
    SHA256(plaintext, plaintext_len, hash);
    char hash_hex[65];
    for(int i=0; i<32; i++) sprintf(hash_hex + 2*i, "%02x", hash[i]);
    debug_log("Packet hash: %s\n", hash_hex);
    
    if (hash_table_find(bank->recent_messages, hash_hex)) {
        debug_log("DROPPED: Replay detected! This packet was seen before.\n");
        return;
    }
    debug_log("Replay check: PASSED (new packet)\n");
    
    // Add to cache
    uint64_t *ts_ptr = malloc(sizeof(uint64_t));
    *ts_ptr = timestamp;
    char *hash_key = strdup(hash_hex);
    hash_table_add(bank->recent_messages, hash_key, ts_ptr);
    list_add(bank->replay_cleanup_list, hash_key, ts_ptr);
    debug_log("Packet added to replay cache\n");

    // Cleanup Replay Cache
    int cleaned = 0;
    while (bank->replay_cleanup_list->head) {
        ListElem *head = bank->replay_cleanup_list->head;
        uint64_t *ts = (uint64_t*)head->val;
        if (current_time > *ts + 65) {
            hash_table_del(bank->recent_messages, head->key);
            bank->replay_cleanup_list->head = head->next;
            if (bank->replay_cleanup_list->head == NULL) {
                bank->replay_cleanup_list->tail = NULL;
            }
            bank->replay_cleanup_list->size--;
            free(head->key);
            free(head->val);
            free(head);
            cleaned++;
        } else {
            break;
        }
    }
    if (cleaned > 0) {
        debug_log("Cleaned %d expired entries from replay cache\n", cleaned);
    }

    // Process Command
    unsigned char response_data[1024];
    int response_len = 0;
    int status = 1; // Default error

    if (cmd_type == 0x01) { // BEGIN_SESSION
        debug_log("=== Processing BEGIN_SESSION ===\n");
        
        if (data_len < 1) {
            debug_log("REJECTED: data_len < 1\n");
            return;
        }
        int user_len = data[0];
        debug_log("user_len from packet: %d\n", user_len);
        
        if (data_len < 1 + user_len + 32) {
            debug_log("REJECTED: data_len (%d) < required (%d)\n", data_len, 1 + user_len + 32);
            return;
        }
        
        // Fix: Buffer Overflow
        if (user_len > 250) {
            debug_log("REJECTED: user_len > 250 (buffer overflow protection)\n");
            return;
        }

        char username[251];
        memcpy(username, data + 1, user_len);
        username[user_len] = '\0';
        debug_log("Username: '%s'\n", username);
        
        unsigned char *user_key = data + 1 + user_len;
        print_hex("Received user_key", user_key, 32);

        // Check if session active - also check for server-side timeout
        debug_log("Checking existing session for '%s'...\n", username);
        SessionData *existing_sd = hash_table_find(bank->active_sessions, username);
        if (existing_sd) {
            debug_log("Found existing session: session_id=0x%016lx, last_active=%ld (%ld sec ago)\n",
                      (unsigned long)existing_sd->session_id, 
                      (long)existing_sd->last_active,
                      (long)(current_time - existing_sd->last_active));
            
            // Check if the existing session has timed out (server-side timeout: 120 seconds)
            if (current_time - existing_sd->last_active > 120) {
                debug_log("Session expired (>120s), cleaning up\n");
                hash_table_del(bank->active_sessions, username);
                free(existing_sd);
                existing_sd = NULL;
            } else {
                debug_log("Session still active, rejecting new session\n");
                status = 1;
            }
        } else {
            debug_log("No existing session found\n");
        }
        
        if (!existing_sd) {
            debug_log("Looking up user '%s' in database...\n", username);
            User *u = hash_table_find(bank->users, username);
            if (u) {
                debug_log("User found: username='%s', balance=$%d\n", u->username, u->balance);
                print_hex("Stored user_key", u->user_key, 32);
                
                int key_match = (memcmp(u->user_key, user_key, 32) == 0);
                debug_log("User key comparison: %s\n", key_match ? "MATCH" : "NO MATCH");
                
                if (key_match) {
                    // Auth success
                    debug_log("Authentication SUCCESS!\n");
                    SessionData *sd = malloc(sizeof(SessionData));
                    sd->last_active = current_time;
                    RAND_bytes((unsigned char*)&sd->session_id, 8);
                    
                    debug_log("Created new session:\n");
                    debug_log("  session_id: 0x%016lx\n", (unsigned long)sd->session_id);
                    debug_log("  last_active: %ld\n", (long)sd->last_active);
                    
                    hash_table_add(bank->active_sessions, strdup(username), sd);
                    status = 0;
                    
                    // Return Session ID
                    memcpy(response_data, &sd->session_id, 8);
                    response_len = 8;
                    debug_log("Session added to active_sessions table\n");
                } else {
                    debug_log("Authentication FAILED (key mismatch)\n");
                    status = 1;
                }
            } else {
                debug_log("Authentication FAILED (user not found)\n");
                status = 1;
            }
        }
        debug_log("=== BEGIN_SESSION complete, status=%d ===\n", status);
        
    } else {
        // Other commands require active session
        debug_log("=== Processing %s ===\n", cmd_type_str(cmd_type));
        
        // Format: [SessionID(8)][UserLen(1)][Username(UserLen)][Data...]
        if (data_len < 9) {
            debug_log("REJECTED: data_len (%d) < 9 (need session_id + user_len)\n", data_len);
            return;
        }
        
        uint64_t sess_id;
        memcpy(&sess_id, data, 8);
        debug_log("Session ID from packet: 0x%016lx\n", (unsigned long)sess_id);
        
        int user_len = data[8];
        if (data_len < 9 + user_len) {
            debug_log("REJECTED: data_len (%d) < required (%d)\n", data_len, 9 + user_len);
            return;
        }
        
        // Fix: Buffer Overflow
        if (user_len > 250) {
            debug_log("REJECTED: user_len > 250 (buffer overflow protection)\n");
            return;
        }

        char username[251];
        memcpy(username, data + 9, user_len);
        username[user_len] = '\0';
        debug_log("Username: '%s'\n", username);

        debug_log("Looking up session for '%s'...\n", username);
        SessionData *sd = hash_table_find(bank->active_sessions, username);
        if (!sd) {
            debug_log("Session lookup FAILED: No session for user\n");
            status = 1; // No session
        } else {
            debug_log("Session found: session_id=0x%016lx, last_active=%ld\n",
                      (unsigned long)sd->session_id, (long)sd->last_active);
            
            // Check Session ID
            if (sd->session_id != sess_id) {
                debug_log("Session ID MISMATCH: stored=0x%016lx, received=0x%016lx\n",
                          (unsigned long)sd->session_id, (unsigned long)sess_id);
                status = 1;
            } 
            // Check session timeout (5 mins)
            else if (current_time - sd->last_active > 300) {
                debug_log("Session EXPIRED: last_active was %ld seconds ago (>300s limit)\n",
                          (long)(current_time - sd->last_active));
                hash_table_del(bank->active_sessions, username);
                free(sd);
                status = 1;
            } else {
                debug_log("Session validation: PASSED\n");
                sd->last_active = current_time;
                debug_log("Updated last_active to %ld\n", (long)sd->last_active);
                
                if (cmd_type == 0x02) { // WITHDRAW
                    debug_log("--- WITHDRAW operation ---\n");
                    
                    if (data_len < 9 + user_len + 4) {
                        debug_log("REJECTED: Insufficient data for amount\n");
                        return;
                    }
                    int amt;
                    memcpy(&amt, data + 9 + user_len, 4);
                    debug_log("Withdrawal amount: $%d\n", amt);
                    
                    // Fix: Negative Withdrawal
                    if (amt <= 0) {
                        debug_log("REJECTED: Invalid amount (<=0)\n");
                        status = 1;
                    } else {
                        User *u = hash_table_find(bank->users, username);
                        if (u) {
                            debug_log("User balance: $%d\n", u->balance);
                            if (u->balance >= amt) {
                                u->balance -= amt;
                                debug_log("Withdrawal SUCCESS: new balance=$%d\n", u->balance);
                                status = 0;
                            } else {
                                debug_log("REJECTED: Insufficient funds ($%d < $%d)\n", u->balance, amt);
                                status = 1;
                            }
                        } else {
                            debug_log("ERROR: User not found in database?!\n");
                            status = 1;
                        }
                    }
                } else if (cmd_type == 0x03) { // BALANCE
                    debug_log("--- BALANCE query ---\n");
                    
                    User *u = hash_table_find(bank->users, username);
                    if (u) {
                        debug_log("Balance for '%s': $%d\n", username, u->balance);
                        status = 0;
                        memcpy(response_data, &u->balance, 4);
                        response_len = 4;
                    } else {
                        debug_log("ERROR: User not found in database?!\n");
                        status = 1;
                    }
                } else if (cmd_type == 0x04) { // END_SESSION
                    debug_log("--- END_SESSION ---\n");
                    debug_log("Removing session for '%s'\n", username);
                    
                    hash_table_del(bank->active_sessions, username);
                    free(sd);
                    status = 0;
                    debug_log("Session ended successfully\n");
                } else {
                    debug_log("REJECTED: Unknown command type 0x%02x\n", cmd_type);
                    status = 1;
                }
            }
        }
        debug_log("=== %s complete, status=%d ===\n", cmd_type_str(cmd_type), status);
    }

    // Send Response
    debug_log("\n--- Building Response ---\n");
    print_response_packet(status, response_len, response_data);
    
    unsigned char resp_plaintext[2048];
    uint64_t resp_ts = time(NULL);
    memcpy(resp_plaintext, &resp_ts, 8);
    resp_plaintext[8] = status;
    uint16_t rlen = response_len;
    memcpy(resp_plaintext + 9, &rlen, 2);
    memcpy(resp_plaintext + 11, response_data, response_len);
    
    int resp_plain_len = 11 + response_len;
    debug_log("Response plaintext: %d bytes\n", resp_plain_len);
    print_hex("Response plaintext", resp_plaintext, resp_plain_len);
    
    unsigned char resp_iv[16];
    RAND_bytes(resp_iv, 16);
    
    unsigned char resp_ciphertext[2048];
    int resp_c_len = encrypt_msg(bank->K_enc, resp_iv, resp_plaintext, resp_plain_len, resp_ciphertext);
    
    unsigned char resp_msg[4096];
    memcpy(resp_msg, resp_iv, 16);
    memcpy(resp_msg + 16, resp_ciphertext, resp_c_len);
    
    unsigned char resp_mac[32];
    unsigned int mac_len;
    HMAC(EVP_sha256(), bank->K_mac, 32, resp_msg, 16 + resp_c_len, resp_mac, &mac_len);
    memcpy(resp_msg + 16 + resp_c_len, resp_mac, 32);
    
    debug_log("Response packet: IV(16) + Ciphertext(%d) + MAC(32) = %d bytes\n",
              resp_c_len, 16 + resp_c_len + 32);
    print_hex("Response MAC", resp_mac, 32);
    
    bank_send(bank, (char*)resp_msg, 16 + resp_c_len + 32);
    debug_log("--- Response Sent ---\n\n");
}
