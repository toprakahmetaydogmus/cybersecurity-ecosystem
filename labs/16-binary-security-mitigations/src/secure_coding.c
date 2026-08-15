/*
 * Binary Security & Hardening Demonstration
 * Author: Toprak Ahmet Aydoğmuş
 */
#include <stdio.h>
#include <string.h>

void safe_string_copy(const char *user_input) {
    char destination_buffer[64];
    // Secure bounds-checking prevents buffer overflow
    strncpy(destination_buffer, user_input, sizeof(destination_buffer) - 1);
    destination_buffer[sizeof(destination_buffer) - 1] = '\0';
    printf("[+] Buffer processed securely: %s\n", destination_buffer);
}

int main() {
    printf("[*] Binary Mitigations Lab Initialized.\n");
    safe_string_copy("Secure string within safe boundaries.");
    return 0;
}
