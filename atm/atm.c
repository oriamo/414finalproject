#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/time.h> 

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

ATM* atm_create(char *init_filename)
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    printf("ATM Port: %d\n", ATM_PORT);

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
    FILE *f = fopen(init_filename, "rb");
    if (!f) {
        printf("Error opening ATM initialization file\n");
        exit(64);
    }
    if (fread(atm->K_enc, 1, 32, f) != 32 || fread(atm->K_mac, 1, 32, f) != 32) {
        printf("Error opening ATM initialization file\n");
        exit(64);
    }
    fclose(f);

    atm->session_active = 0;
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
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command)
{
    // Remove newline
    size_t len = strlen(command);
    if (len > 0 && command[len-1] == '\n') {
        command[len-1] = '\0';
        len--;
    }

    // Check Timeout
    if (atm->session_active) {
        time_t current_time = time(NULL);
        if (current_time - atm->last_activity_time > 60) {
            printf("Session timed out due to inactivity\n");
            
            // Send END_SESSION
            unsigned char plaintext[2048];
            uint64_t ts = current_time;
            memcpy(plaintext, &ts, 8);
            plaintext[8] = 0x04; // END_SESSION
            int user_len = strlen(atm->current_user);
            plaintext[9] = user_len;
            memcpy(plaintext + 10, atm->current_user, user_len);
            int plain_len = 10 + user_len;

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

            atm->session_active = 0;
            memset(atm->current_user, 0, sizeof(atm->current_user));
            
            // Reject current command
            // But wait, if I just timed out, I should probably not process the command.
            // The prompt will change back to "ATM: " in main loop.
            return;
        }
    }

    char cmd_copy[1000];
    strncpy(cmd_copy, command, 1000);
    char *token = strtok(cmd_copy, " ");
    if (!token) return;

    if (strcmp(token, "begin-session") == 0) {
        if (atm->session_active) {
            printf("A user is already logged in\n");
            return;
        }

        char *user_arg = strtok(NULL, " ");
        if (!user_arg || strtok(NULL, " ")) {
            printf("Usage: begin-session <user-name>\n");
            return;
        }

        // Validate username
        if (strlen(user_arg) > 250) {
             printf("Usage: begin-session <user-name>\n");
             return;
        }
        for (int i=0; user_arg[i]; i++) {
            if (!((user_arg[i] >= 'a' && user_arg[i] <= 'z') || (user_arg[i] >= 'A' && user_arg[i] <= 'Z'))) {
                printf("Usage: begin-session <user-name>\n");
                return;
            }
        }

        // Check card file
        char card_filename[300];
        sprintf(card_filename, "%s.card", user_arg);
        if (access(card_filename, F_OK) != 0) {
            printf("Unable to access %s's card\n", user_arg);
            return;
        }

        printf("PIN? ");
        fflush(stdout);
        char pin[100];
        if (!fgets(pin, 100, stdin)) return;
        size_t pin_len = strlen(pin);
        if (pin_len > 0 && pin[pin_len-1] == '\n') pin[pin_len-1] = '\0';

        if (strlen(pin) != 4) {
            printf("Not authorized\n");
            return;
        }
        for(int i=0; i<4; i++) if(pin[i] < '0' || pin[i] > '9') {
            printf("Not authorized\n");
            return;
        }

        // Decrypt Card
        FILE *cf = fopen(card_filename, "rb");
        unsigned char card_iv[16];
        unsigned char card_ciphertext[64];
        fread(card_iv, 1, 16, cf);
        int card_c_len = fread(card_ciphertext, 1, 64, cf);
        fclose(cf);

        unsigned char pin_key[32];
        SHA256((unsigned char*)pin, 4, pin_key);

        unsigned char user_key[32];
        // We expect 32 bytes of user key.
        // Decrypt
        unsigned char decrypted_card[64];
        int d_len = decrypt_msg(pin_key, card_iv, card_ciphertext, card_c_len, decrypted_card);
        
        // If decryption fails or length is wrong, it's wrong PIN (likely)
        // But AES-CBC doesn't guarantee integrity. We just get garbage.
        // We send garbage to bank.
        if (d_len != 32) {
            // It might be padding issues if key is wrong.
            // We can just proceed with whatever we got or fail here.
            // Spec says "If the PIN entered is invalid... or if it is unable to authenticate... print Not authorized".
            // We'll send to bank to confirm.
            // If d_len is not 32, we can pad or truncate, or just fail.
            // But better to let bank reject it to avoid timing leaks?
            // Actually, if d_len is wrong, we know it's wrong PIN locally if we assume card file is valid.
            // But let's just use what we have.
        }
        memcpy(user_key, decrypted_card, 32);

        // Send to Bank
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x01; // BEGIN_SESSION
        int user_len = strlen(user_arg);
        plaintext[9] = user_len;
        memcpy(plaintext + 10, user_arg, user_len);
        memcpy(plaintext + 10 + user_len, user_key, 32);
        int plain_len = 10 + user_len + 32;

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

        // Wait for response
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            printf("Not authorized\n"); // Timeout or error
            return;
        }

        // Verify Response
        if (n < 48) { printf("Not authorized\n"); return; }
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            printf("Not authorized\n"); return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) { printf("Not authorized\n"); return; }

        // Check status
        if (r_plain[8] == 0) {
            printf("Authorized\n");
            atm->session_active = 1;
            strcpy(atm->current_user, user_arg);
            atm->last_activity_time = time(NULL);
        } else {
            printf("Not authorized\n");
        }

    } else if (strcmp(token, "withdraw") == 0) {
        if (!atm->session_active) {
            printf("No user logged in\n");
            return;
        }
        
        char *amt_arg = strtok(NULL, " ");
        if (!amt_arg || strtok(NULL, " ")) {
            printf("Usage: withdraw <amt>\n");
            return;
        }

        char *endptr;
        long val = strtol(amt_arg, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 2147483647) {
             printf("Usage: withdraw <amt>\n");
             return;
        }
        int amt = (int)val;

        // Send WITHDRAW
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x02; // WITHDRAW
        int user_len = strlen(atm->current_user);
        plaintext[9] = user_len;
        memcpy(plaintext + 10, atm->current_user, user_len);
        memcpy(plaintext + 10 + user_len, &amt, 4);
        int plain_len = 10 + user_len + 4;

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

        // Wait response
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            printf("Transaction failed\n"); // Timeout
            return;
        }

        // Verify Response
        if (n < 48) { printf("Transaction failed\n"); return; }
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            printf("Transaction failed\n"); return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) { printf("Transaction failed\n"); return; }

        if (r_plain[8] == 0) {
            printf("$%d dispensed\n", amt);
        } else {
            printf("Insufficient funds\n");
        }
        atm->last_activity_time = time(NULL);

    } else if (strcmp(token, "balance") == 0) {
        if (!atm->session_active) {
            printf("No user logged in\n");
            return;
        }
        
        if (strtok(NULL, " ")) {
            printf("Usage: balance\n");
            return;
        }

        // Send BALANCE
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x03; // BALANCE
        int user_len = strlen(atm->current_user);
        plaintext[9] = user_len;
        memcpy(plaintext + 10, atm->current_user, user_len);
        int plain_len = 10 + user_len;

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

        // Wait response
        char resp_buf[4096];
        int n = atm_recv(atm, resp_buf, 4096);
        if (n < 0) {
            printf("Transaction failed\n"); // Timeout
            return;
        }

        // Verify Response
        if (n < 48) { printf("Transaction failed\n"); return; }
        unsigned char *r_iv = (unsigned char*)resp_buf;
        unsigned char *r_c = (unsigned char*)resp_buf + 16;
        unsigned char *r_mac = (unsigned char*)resp_buf + n - 32;
        int r_c_len = n - 48;

        if (!verify_mac(atm->K_mac, (unsigned char*)resp_buf, n - 32, r_mac)) {
            printf("Transaction failed\n"); return;
        }

        unsigned char r_plain[2048];
        int r_p_len = decrypt_msg(atm->K_enc, r_iv, r_c, r_c_len, r_plain);
        if (r_p_len < 11) { printf("Transaction failed\n"); return; }

        if (r_plain[8] == 0) {
            int bal;
            memcpy(&bal, r_plain + 11, 4);
            printf("$%d\n", bal);
        } else {
            printf("Transaction failed\n");
        }
        atm->last_activity_time = time(NULL);

    } else if (strcmp(token, "end-session") == 0) {
        if (!atm->session_active) {
            printf("No user logged in\n");
            return;
        }

        // Send END_SESSION
        unsigned char plaintext[2048];
        uint64_t ts = time(NULL);
        memcpy(plaintext, &ts, 8);
        plaintext[8] = 0x04; // END_SESSION
        int user_len = strlen(atm->current_user);
        plaintext[9] = user_len;
        memcpy(plaintext + 10, atm->current_user, user_len);
        int plain_len = 10 + user_len;

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

        // Don't wait for response, just logout locally
        atm->session_active = 0;
        memset(atm->current_user, 0, sizeof(atm->current_user));
        printf("User logged out\n");

    } else {
        printf("Invalid command\n");
    }
}
