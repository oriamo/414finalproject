/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char**argv)
{
    char user_input[1000];

    if (argc != 2) {
        printf("Usage: atm <init-filename>\n");
        return 64;
    }

    ATM *atm = atm_create(argv[1]);

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 1000,stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        if (atm->session_active) {
            printf("ATM (%s):  ", atm->current_user);
        } else {
            printf("ATM: ");
        }
        fflush(stdout);
    }
	return EXIT_SUCCESS;
}
