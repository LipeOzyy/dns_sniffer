# modo de usar: ./dns_sniffer exemplo.com wordlist.txt 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

void print_banner() {
    printf("=============================================\n");
    printf("                DNS SNIFFER                  \n");
    printf("      Ferramenta de Brute Force de DNS       \n");
    printf("                by LipeOzyy                  \n");
    printf("=============================================\n\n");
}

void dns_bruteforce(const char *domain, const char *wordlist_file) {
    FILE *file;
    char subdomain[256];
    char hostname[512];
    struct hostent *host;

    file = fopen(wordlist_file, "r");
    if (file == NULL) {
        perror("Erro ao abrir o arquivo da wordlist");
        exit(EXIT_FAILURE);
    }

    while (fgets(subdomain, sizeof(subdomain), file)) {
        
        subdomain[strcspn(subdomain, "\n")] = '\0';

        snprintf(hostname, sizeof(hostname), "%s.%s", subdomain, domain);

        host = gethostbyname(hostname);
        if (host != NULL) {

            printf("Subdomínio encontrado: %s -> %s\n", hostname, inet_ntoa(*(struct in_addr *)host->h_addr));
        }
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    // Imprime o banner da ferramenta
    print_banner();

    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dominio> <wordlist>\n", argv[0]);
        return EXIT_FAILURE;
    }

    
    const char *domain = argv[1];
    const char *wordlist_file = argv[2];

    dns_bruteforce(domain, wordlist_file);

    return EXIT_SUCCESS;
}
