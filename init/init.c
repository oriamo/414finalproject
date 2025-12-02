#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: init <filename>\n");
        return 62;
    }

    char *filename = argv[1];
    char atm_filename[256];
    char bank_filename[256];

    // Construct filenames
    snprintf(atm_filename, sizeof(atm_filename), "%s.atm", filename);
    snprintf(bank_filename, sizeof(bank_filename), "%s.bank", filename);

    // Check if files exist
    if (access(atm_filename, F_OK) == 0 || access(bank_filename, F_OK) == 0) {
        printf("Error: one of the files already exists\n");
        return 63;
    }

    // Generate keys
    unsigned char k_enc[32];
    unsigned char k_mac[32];

    if (RAND_bytes(k_enc, 32) != 1 || RAND_bytes(k_mac, 32) != 1) {
        printf("Error creating initialization files\n");
        return 64;
    }

    // Write .atm file
    FILE *atm_file = fopen(atm_filename, "wb");
    if (!atm_file) {
        printf("Error creating initialization files\n");
        return 64;
    }
    
    if (fwrite(k_enc, 1, 32, atm_file) != 32 || fwrite(k_mac, 1, 32, atm_file) != 32) {
        fclose(atm_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    fclose(atm_file);

    // Write .bank file
    FILE *bank_file = fopen(bank_filename, "wb");
    if (!bank_file) {
        printf("Error creating initialization files\n");
        return 64;
    }
    
    if (fwrite(k_enc, 1, 32, bank_file) != 32 || fwrite(k_mac, 1, 32, bank_file) != 32) {
        fclose(bank_file);
        printf("Error creating initialization files\n");
        return 64;
    }
    fclose(bank_file);

    printf("Successfully initialized bank state\n");
    return 0;
}
