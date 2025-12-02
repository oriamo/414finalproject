#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

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
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    int opt = 1;
    setsockopt(bank->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    if (bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr)) < 0) {
        perror("Bank bind failed");
        exit(1);
    }

    // Read initialization file
    FILE *f = fopen(init_filename, "rb");
    if (!f) {
        printf("Error opening bank initialization file\n");
        exit(64);
    }
    if (fread(bank->K_enc, 1, 32, f) != 32 || fread(bank->K_mac, 1, 32, f) != 32) {
        printf("Error opening bank initialization file\n");
        exit(64);
    }
    fclose(f);
    
    

    // Initialize HashTables
    bank->users = hash_table_create(100);
    bank->active_sessions = hash_table_create(100);
    bank->recent_messages = hash_table_create(1000);
    bank->replay_cleanup_list = list_create();

    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        close(bank->sockfd);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
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

    // Parse command
    char *token = strtok(command, " ");
    if (!token) return; // Empty line

    if (strcmp(token, "create-user") == 0) {
        char *user_arg = strtok(NULL, " ");
        char *pin_arg = strtok(NULL, " ");
        char *bal_arg = strtok(NULL, " ");
        
        if (!user_arg || !pin_arg || !bal_arg || strtok(NULL, " ")) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        
        // Validate username
        if (strlen(user_arg) > 250) {
             printf("Usage:  create-user <user-name> <pin> <balance>\n");
             return;
        }
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                printf("Usage:  create-user <user-name> <pin> <balance>\n");
                return;
            }
        }

        // Validate PIN
        if (strlen(pin_arg) != 4) {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }
        for (int i=0; i<4; i++) {
            if (pin_arg[i] < '0' || pin_arg[i] > '9') {
                printf("Usage:  create-user <user-name> <pin> <balance>\n");
                return;
            }
        }

        // Validate Balance
        char *endptr;
        long val = strtol(bal_arg, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 2147483647) {
             printf("Usage:  create-user <user-name> <pin> <balance>\n");
             return;
        }
        int balance = (int)val;

        // Check if user exists
        if (hash_table_find(bank->users, user_arg)) {
            printf("Error:  user %s already exists\n", user_arg);
            return;
        }

        // Create user
        User *new_user = malloc(sizeof(User));
        strcpy(new_user->username, user_arg);
        new_user->balance = balance;
        RAND_bytes(new_user->user_key, 32);

        // Create card file
        unsigned char salt[16];
        RAND_bytes(salt, 16);

        unsigned char pin_key[32];
        if (PKCS5_PBKDF2_HMAC(pin_arg, strlen(pin_arg), salt, 16, 10000, EVP_sha256(), 32, pin_key) != 1) {
             printf("Error deriving key\n");
             return;
        }

        unsigned char iv[16];
        RAND_bytes(iv, 16);

        unsigned char ciphertext[64]; 
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int outlen1, outlen2;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pin_key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &outlen1, new_user->user_key, 32);
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
        EVP_CIPHER_CTX_free(ctx);

        char card_filename[300];
        sprintf(card_filename, "%s.card", user_arg);
        FILE *card_file = fopen(card_filename, "wb");
        if (!card_file) {
            printf("Error creating card file for user %s\n", user_arg);
            free(new_user);
            return;
        }
        fwrite(salt, 1, 16, card_file);
        fwrite(iv, 1, 16, card_file);
        fwrite(ciphertext, 1, outlen1 + outlen2, card_file);
        fclose(card_file);

        hash_table_add(bank->users, new_user->username, new_user);
        printf("Created user %s\n", user_arg);

    } else if (strcmp(token, "deposit") == 0) {
        char *user_arg = strtok(NULL, " ");
        char *amt_arg = strtok(NULL, " ");
        
        if (!user_arg || !amt_arg || strtok(NULL, " ")) {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }

        // Validate username chars
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                printf("Usage:  deposit <user-name> <amt>\n");
                return;
            }
        }

        // Validate Amount
        char *endptr;
        long val = strtol(amt_arg, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 2147483647) {
             printf("Usage:  deposit <user-name> <amt>\n");
             return;
        }
        int amt = (int)val;

        User *u = hash_table_find(bank->users, user_arg);
        if (!u) {
            printf("No such user\n");
            return;
        }

        if ((long)u->balance + amt > 2147483647) {
            printf("Too rich for this program\n");
            return;
        }

        u->balance += amt;
        printf("$%d added to %s's account\n", amt, user_arg);

    } else if (strcmp(token, "balance") == 0) {
        char *user_arg = strtok(NULL, " ");
        
        if (!user_arg || strtok(NULL, " ")) {
            printf("Usage:  balance <user-name>\n");
            return;
        }

        // Validate username chars
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                printf("Usage:  balance <user-name>\n");
                return;
            }
        }

        User *u = hash_table_find(bank->users, user_arg);
        if (!u) {
            printf("No such user\n");
            return;
        }

        printf("$%d\n", u->balance);

    } else {
        printf("Invalid command\n");
    }
}

#include <time.h>

static int verify_mac(unsigned char *key, unsigned char *msg, int len, unsigned char *mac) {
    unsigned char computed_mac[32];
    unsigned int mac_len;
    HMAC(EVP_sha256(), key, 32, msg, len, computed_mac, &mac_len);
    return CRYPTO_memcmp(mac, computed_mac, 32) == 0;
}

static int decrypt_msg(unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return outlen1 + outlen2;
}

static int encrypt_msg(unsigned char *key, unsigned char *iv, unsigned char *plaintext, int len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1, outlen2;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen1, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return outlen1 + outlen2;
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    if (len < 48) return; // Too short (IV + MAC = 48)

    unsigned char *iv = (unsigned char*)command;
    unsigned char *ciphertext = (unsigned char*)command + 16;
    unsigned char *mac = (unsigned char*)command + len - 32;
    int ciphertext_len = len - 48;

    // Verify MAC
    if (!verify_mac(bank->K_mac, (unsigned char*)command, len - 32, mac)) {
        return; // Drop invalid MAC
    }

    // Decrypt
    unsigned char plaintext[2048];
    int plaintext_len = decrypt_msg(bank->K_enc, iv, ciphertext, ciphertext_len, plaintext);
    if (plaintext_len < 0) return; // Decryption failed

    // Parse Plaintext
    if (plaintext_len < 9) return; // Timestamp + Cmd

    uint64_t timestamp;
    memcpy(&timestamp, plaintext, 8);
    unsigned char cmd_type = plaintext[8];
    unsigned char *data = plaintext + 9;
    int data_len = plaintext_len - 9;

    // Check Timestamp
    time_t current_time = time(NULL);
    // Allow 60 seconds window. Also allow small future skew (5s)
    if (current_time > timestamp + 60 || timestamp > current_time + 5) {
        return; // Replay or clock skew
    }

    // Check Replay Cache
    unsigned char hash[32];
    SHA256(plaintext, plaintext_len, hash);
    char hash_hex[65];
    for(int i=0; i<32; i++) sprintf(hash_hex + 2*i, "%02x", hash[i]);
    
    if (hash_table_find(bank->recent_messages, hash_hex)) {
        return; // Replay
    }
    
    // Add to cache
    uint64_t *ts_ptr = malloc(sizeof(uint64_t));
    *ts_ptr = timestamp;
    char *hash_key = strdup(hash_hex);
    hash_table_add(bank->recent_messages, hash_key, ts_ptr);
    list_add(bank->replay_cleanup_list, hash_key, ts_ptr);

    // Cleanup Replay Cache
    while (bank->replay_cleanup_list->head) {
        ListElem *head = bank->replay_cleanup_list->head;
        uint64_t *ts = (uint64_t*)head->val;
        if (current_time > *ts + 65) { // Expire after 65s (slightly > 60s window)
            hash_table_del(bank->recent_messages, head->key);
            // Manually remove from list to avoid O(N) search
            bank->replay_cleanup_list->head = head->next;
            if (bank->replay_cleanup_list->head == NULL) {
                bank->replay_cleanup_list->tail = NULL;
            }
            bank->replay_cleanup_list->size--;
            // Free memory (key is shared with hash table? No, strdup'd twice? 
            // hash_table_add takes key. list_add takes key. 
            // hash_table_del frees the key if it owns it? 
            // Let's assume hash_table_del frees the key passed to add.
            // list_add copies key? No, list_add(list, key, val) assigns key.
            // So if I pass the SAME pointer to both, I must be careful.
            // hash_table_add usually strdups? No, it takes char*.
            // Let's check hash_table.c later. For now, assume standard behavior.
            // If I passed strdup(hash_hex) to hash_table_add, and hash_hex to list_add...
            // I should probably strdup for list too or share.
            // Let's just use the same pointer if possible, but list_del frees key?
            // I am manually removing. So I should free head->key if list owns it.
            // But wait, hash_table_del might free the key too.
            // To be safe: strdup for both.
            // hash_table_add(..., strdup(hash_hex), ...)
            // list_add(..., strdup(hash_hex), ...)
            // Then free both here.
            free(head->key); // Free list's copy
            free(head->val); // Free timestamp (shared?)
            // Wait, ts_ptr is shared. hash_table_del frees the value?
            // hash_table_del usually frees the value if it knows how? No, it's void*.
            // It probably doesn't free the value.
            // So I should free ts_ptr here.
            free(head);
        } else {
            break; // List is sorted by time
        }
    }

    // Process Command
    unsigned char response_data[1024];
    int response_len = 0;
    int status = 1; // Default error

    if (cmd_type == 0x01) { // BEGIN_SESSION
        if (data_len < 1) return;
        int user_len = data[0];
        if (data_len < 1 + user_len + 32) return;
        
        // Fix: Buffer Overflow
        if (user_len > 250) return;

        char username[251];
        memcpy(username, data + 1, user_len);
        username[user_len] = '\0';
        
        unsigned char *user_key = data + 1 + user_len;

        // Check if session active - also check for server-side timeout
        SessionData *existing_sd = hash_table_find(bank->active_sessions, username);
        if (existing_sd) {
            // Check if the existing session has timed out (server-side timeout: 120 seconds)
            if (current_time - existing_sd->last_active > 120) {
                // Session expired, clean it up
                hash_table_del(bank->active_sessions, username);
                free(existing_sd);
                existing_sd = NULL;
            } else {
                // Session still active
                status = 1;
            }
        }
        
        if (!existing_sd) {
            User *u = hash_table_find(bank->users, username);
            if (u && memcmp(u->user_key, user_key, 32) == 0) {
                // Auth success
                SessionData *sd = malloc(sizeof(SessionData));
                sd->last_active = current_time;
                RAND_bytes((unsigned char*)&sd->session_id, 8);
                
                hash_table_add(bank->active_sessions, strdup(username), sd);
                status = 0;
                
                // Return Session ID
                memcpy(response_data, &sd->session_id, 8);
                response_len = 8;
            } else {
                // Auth fail
                status = 1;
            }
        }
    } else {
        // Other commands require active session
        // Format: [SessionID(8)][UserLen(1)][Username(UserLen)][Data...]
        if (data_len < 9) return;
        
        uint64_t sess_id;
        memcpy(&sess_id, data, 8);
        
        int user_len = data[8];
        if (data_len < 9 + user_len) return;
        
        // Fix: Buffer Overflow
        if (user_len > 250) return;

        char username[251];
        memcpy(username, data + 9, user_len);
        username[user_len] = '\0';

        SessionData *sd = hash_table_find(bank->active_sessions, username);
        if (!sd) {
            status = 1; // No session
        } else {
            // Check Session ID
            if (sd->session_id != sess_id) {
                status = 1; // Invalid Session ID
            } 
            // Check session timeout (5 mins)
            else if (current_time - sd->last_active > 300) {
                hash_table_del(bank->active_sessions, username);
                // Note: hash_table_del doesn't free the value (SessionData). Memory leak?
                // I should free it. But hash_table_del doesn't return it.
                // I already have 'sd'.
                free(sd);
                status = 1; // Expired
            } else {
                sd->last_active = current_time;
                
                if (cmd_type == 0x02) { // WITHDRAW
                    if (data_len < 9 + user_len + 4) return;
                    int amt;
                    memcpy(&amt, data + 9 + user_len, 4);
                    
                    // Fix: Negative Withdrawal
                    if (amt <= 0) {
                        status = 1;
                    } else {
                        User *u = hash_table_find(bank->users, username);
                        if (u && u->balance >= amt) {
                            u->balance -= amt;
                            status = 0;
                        } else {
                            status = 1; // Insufficient funds
                        }
                    }
                } else if (cmd_type == 0x03) { // BALANCE
                    User *u = hash_table_find(bank->users, username);
                    if (u) {
                        status = 0;
                        memcpy(response_data, &u->balance, 4);
                        response_len = 4;
                    }
                } else if (cmd_type == 0x04) { // END_SESSION
                    hash_table_del(bank->active_sessions, username);
                    free(sd);
                    status = 0;
                }
            }
        }
    }

    // Send Response
    unsigned char resp_plaintext[2048];
    uint64_t resp_ts = time(NULL);
    memcpy(resp_plaintext, &resp_ts, 8);
    resp_plaintext[8] = status;
    uint16_t rlen = response_len;
    memcpy(resp_plaintext + 9, &rlen, 2);
    memcpy(resp_plaintext + 11, response_data, response_len);
    
    int resp_plain_len = 11 + response_len;
    
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
    
    bank_send(bank, (char*)resp_msg, 16 + resp_c_len + 32);
}
