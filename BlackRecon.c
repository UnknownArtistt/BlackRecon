#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void showBanner() {
    printf("\n------------------------------------------------------\n");
    system("figlet -f slant BlackRecon");
    printf("            [+] Coded By AbyssWatcher [+]\n");
    printf("------------------------------------------------------\n\n");
}

void showMenu() {

    printf(" ------------------------------------------\n");
    printf("| >Be welcomed to the depths of the Abyss< |\n");
    printf(" ------------------------------------------\n");

    printf("\n1. Basic Scans\n");
    printf("\t[1] Active Host Scan\n");
    printf("\t[2] Open Port Scan\n");
    printf("\t[3] Specific Port Scan\n");
    printf("\t[4] List Scan\n");

    printf("\n2. Advanced Scans\n");
    printf("\t[5] OS Scan\n");
    printf("\t[6] Full Network Scan (OS, Ports and Services)\n");
    printf("\t[7] Vulnerability Scan\n");
    printf("\t[8] Firewall Detection Scan\n");
    printf("\t[9] Traceroute Scan\n");
    printf("\t[10] IDS Detection Scan\n");

    printf("\n3. Port and Service Scans\n");
    printf("\t[12] TCP Port Scan\n");
    printf("\t[13] UDP Port Scan\n");
    printf("\t[14] Service and Version Scan\n");
    printf("\t[15] Stealth Scan (SYN)\n");
    printf("\t[16] Banner Grabbing Scan\n");
    printf("\t[17] Idle Scan\n");
    printf("\t[18] SCTP Init Scan\n");
    printf("\t[19] SCTP COOKIE-ECHO Scan\n");

    printf("\n4. Aggressive Scans\n");
    printf("\t[20] Intensive Scan\n");
    printf("\t[21] Full Aggressive Scan\n");

    printf("\n5. Scripted Scans\n");
    printf("\t[22] HTTP Enumeration\n");
    printf("\t[23] SMB OS Discovery\n");
    printf("\t[24] DNS Brute Force\n");
    printf("\t[25] DNS Zone Transfer\n");
    printf("\t[26] FTP Anonymous Login\n");
    printf("\t[27] SNMP Information\n");
    printf("\t[28] SSL/TLS Scan\n");
    printf("\t[29] NTP Monlist\n");
    printf("\t[30] SMB Vulnerability Scan\n");

    printf("\n6. Evasion and Fragmentation\n");
    printf("\t[31] Fragmentation Scan\n");
    printf("\t[32] FTP Bounce Scan\n");
    printf("\t[33] Decoy Scan\n");
    printf("\t[34] Randomize Hosts Order\n");
    printf("\t[35] Slow Scan\n");
    printf("\t[36] MAC Address Spoofing\n");
    printf("\t[37] Bad TCP Checksum Scan\n");
    printf("\t[38] IP Protocol Scan\n");

    printf("\n7. Specific Purpose Scans\n");
    printf("\t[39] IPv6 Scan\n");
    printf("\t[41] Timing Templates\n");

    printf("\n8. Saving Results\n");
    printf("\t[42] Save Results in XML\n");
    printf("\t[43] Save Results in Normal Text\n");
    printf("\t[44] Save Results in Grepable Format\n");

    printf("\n9. Show Menu\n");
    printf("\t[45] Show the menu\n");

    printf("\n10. Exit BlackRecon\n");
    printf("\t[46] Exit BlackRecon\n");
}

void showScanInfo(int scanNumber) {
    switch(scanNumber) {
        case 1:
            printf("\nActive Host Scan:\nDescription: Performs a ping scan to discover active hosts in a network without scanning ports.\nCommand: nmap -sn <network>\n");
            break;
        case 2:
            printf("\nOpen Port Scan:\nDescription: Scans open TCP ports on the specified host.\nCommand: nmap <host>\n");
            break;
        case 3:
            printf("\nSpecific Port Scan:\nDescription: Scans specific ports on the specified host.\nCommand: nmap -p <ports> <host>\n");
            break;
        case 4:
            printf("\nList Scan:\nDescription: Lists hosts and DNS names without sending any packets to the network.\nCommand: nmap -sL <target>\n");
            break;
        case 5:
            printf("\nOS Scan:\nDescription: Detects the operating system of the specified host.\nCommand: nmap -O <host>\n");
            break;
        case 6:
            printf("\nFull Network Scan (OS, Ports and Services):\nDescription: Performs a comprehensive scan including OS detection, open ports, and running services.\nCommand: nmap -A <host>\n");
            break;
        case 7:
            printf("\nVulnerability Scan:\nDescription: Uses Nmap Scripting Engine (NSE) scripts to detect known vulnerabilities on the specified host.\nCommand: nmap --script=vuln <host>\n");
            break;
        case 8:
            printf("\nFirewall Detection Scan:\nDescription: Uses TCP ACK scan to detect the presence of a firewall.\nCommand: nmap -sA <host>\n");
            break;
        case 9:
            printf("\nTraceroute Scan:\nDescription: Traces the route packets take to reach the host.\nCommand: nmap --traceroute <host>\n");
            break;
        case 10:
            printf("\nIDS Detection Scan:\nDescription: Detects the presence of an Intrusion Detection System (IDS).\nCommand: nmap --script=firewalk <host>\n");
            break;
        case 12:
            printf("\nTCP Port Scan:\nDescription: Scans TCP ports on the specified host.\nCommand: nmap -sT <host>\n");
            break;
        case 13:
            printf("\nUDP Port Scan:\nDescription: Scans UDP ports on the specified host.\nCommand: nmap -sU <host>\n");
            break;
        case 14:
            printf("\nService and Version Scan:\nDescription: Detects the services and versions running on open ports of the host.\nCommand: nmap -sV <host>\n");
            break;
        case 15:
            printf("\nStealth Scan (SYN):\nDescription: Performs a SYN scan which is less likely to be detected.\nCommand: nmap -sS <host>\n");
            break;
        case 16:
            printf("\nBanner Grabbing Scan:\nDescription: Detects the banner information of the services running on open ports.\nCommand: nmap -sV --script=banner <host>\n");
            break;
        case 17:
            printf("\nIdle Scan:\nDescription: Performs a scan without exposing the scanner's IP address using a zombie host.\nCommand: nmap -sI <zombie host> <target>\n");
            break;
        case 18:
            printf("\nSCTP Init Scan:\nDescription: Scans SCTP ports to detect services using this protocol.\nCommand: nmap -sY <host>\n");
            break;
        case 19:
            printf("\nSCTP COOKIE-ECHO Scan:\nDescription: Detailed SCTP scan using COOKIE-ECHO packets.\nCommand: nmap -sZ <host>\n");
            break;
        case 20:
            printf("\nIntensive Scan:\nDescription: Performs a comprehensive, detailed scan.\nCommand: nmap -T4 -A -v <host>\n");
            break;
        case 21:
            printf("\nFull Aggressive Scan:\nDescription: Performs an aggressive scan with OS detection, version detection, script scanning, and traceroute.\nCommand: nmap -A <host>\n");
            break;
        case 22:
            printf("\nHTTP Enumeration:\nDescription: Enumerates directories, files, and other details from web servers.\nCommand: nmap --script=http-enum <target>\n");
            break;
        case 23:
            printf("\nSMB OS Discovery:\nDescription: Uses SMB protocol to discover the operating system of remote hosts.\nCommand: nmap --script=smb-os-discovery <target>\n");
            break;
        case 24:
            printf("\nDNS Brute Force:\nDescription: Performs DNS brute force enumeration to discover subdomains and hostnames.\nCommand: nmap --script=dns-brute <target>\n");
            break;
        case 25:
            printf("\nDNS Zone Transfer:\nDescription: Attempts a DNS zone transfer to gather detailed DNS records.\nCommand: nmap --script=dns-zone-transfer <target>\n");
            break;
        case 26:
            printf("\nFTP Anonymous Login:\nDescription: Checks if anonymous FTP login is enabled.\nCommand: nmap --script=ftp-anon <target>\n");
            break;
        case 27:
            printf("\nSNMP Information:\nDescription: Gathers information from SNMP-enabled devices. By default this type of SNMP protocol operates in the 161 port.\nCommand: nmap -sU -p <port> --script=snmp-info <host>\n");
            break;
        case 28:
            printf("\nSSL/TLS Scan:\nDescription: Scans for SSL/TLS certificate and cipher information.\nCommand: nmap --script=ssl-cert,ssl-enum-ciphers <host>\n");
            break;
        case 29:
            printf("\nNTP Monlist:\nDescription: Gathers information from NTP servers.\nCommand: nmap -sU -p 123 --script=ntp-monlist <host>\n");
            break;
        case 30:
            printf("\nSMB Vulnerability Scan:\nDescription: Scans for known vulnerabilities in SMB services.\nCommand: nmap --script=smb-vuln-* <host>\n");
            break;
        case 31:
            printf("\nFragmentation Scan:\nDescription: Scans using fragmented packets to evade detection.\nCommand: nmap -f <host>\n");
            break;
        case 32:
            printf("\nFTP Bounce Scan:\nDescription: Scans through an FTP relay host.\nCommand: nmap -b <ftp relay host> <target>\n");
            break;
        case 33:
            printf("\nDecoy Scan:\nDescription: Uses decoy addresses to obscure the real source of the scan.\nCommand: nmap -D RND:10 <host>\n");
            break;
        case 34:
            printf("\nRandomize Hosts Order:\nDescription: Randomizes the order of scanned hosts to evade detection.\nCommand: nmap --randomize-hosts <host>\n");
            break;
        case 35:
            printf("\nSlow Scan:\nDescription: Performs a very slow scan to evade detection.\nCommand: nmap -T0 <host>\n");
            break;
        case 36:
            printf("\nMAC Address Spoofing:\nDescription: Spoofs the MAC address of the scanning system.\nCommand: nmap --spoof-mac <mac address or vendor name> <host>\n");
            break;
        case 37:
            printf("\nBad TCP Checksum Scan:\nDescription: Scans with bad TCP checksums to evade detection.\nCommand: nmap --badsum <host>\n");
            break;
        case 38:
            printf("\nIP Protocol Scan:\nDescription: Scans various IP protocols.\nCommand: nmap -sO <host>\n");
            break;
        case 39:
            printf("\nIPv6 Scan:\nDescription: Scans using IPv6 addresses.\nCommand: nmap -6 <host>\n");
            break;
        case 41:
            printf("\nTiming Templates:\nDescription: Uses different timing templates to adjust scan speed.\nCommand: nmap -T<0-5> <host>\n");
            break;
        case 42:
            printf("\nSave Results in XML:\nDescription: Saves scan results in XML format.\nCommand: nmap -oX resultado.xml <host>\n");
            break;
        case 43:
            printf("\nSave Results in Normal Text:\nDescription: Saves scan results in normal text format.\nCommand: nmap -oN resultado.txt <host>\n");
            break;
        case 44:
            printf("\nSave Results in Grepable Format:\nDescription: Saves scan results in grepable format.\nCommand: nmap -oG resultado.gnmap <host>\n");
            break;
        default:
            printf("\nInvalid scan number.\n");
            break;
    }
}

void executeScan(int scanNumber) {

    char command[256];

    switch (scanNumber)
    {

    // Ping scan, active host    
    case 1:
        {
            char target[100];
            printf("\nEnter the target IP or network name: ");
            scanf("%s", target);
            sprintf(command, "nmap -sn %s", target);
        }
        break;

    // Open port scan
    case 2:
        {
            char host[100];
            printf("\nEnter the target IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap %s", host);
        }
        break;

    //specific port scan
    case 3:
        {
            char port[50], target[100];
            printf("\nEnter the port(s) to scan (e.g 80,443): ");
            scanf("%s", port);
            printf("\nEnter the target IP or hostname: ");
            scanf("%s", target);
            sprintf(command, "nmap -p %s %s", port, target);
        }
        break;

    // List scan
    case 4:
        {
            char target[100];
            printf("\nEnter the network IP or domain name: ");
            scanf("%s", target);
            sprintf(command, "nmap -sL %s", target);
        }
        break;

    // ADVANCED SCANS

    // OS scan
    case 5:
        {
            char host[100];
            printf("\nEnter the host IP or name: ");
            scanf("%s", host);
            sprintf(command, "nmap -O %s", host);
        }
        break;

    // Full network scan (OS, ports and services)
    case 6:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -A %s", host);
        }
        break;

    // vulnerability scan
    case 7:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap--script=vuln %s", host);
        }
        break;

    // firewall detection scan
    case 8:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sA %s", host);
        }
        break;

    // Tracerout scan
    case 9:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --traceroute %s", host);
        }
        break;

    // IDS detection scan
    case 10:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --script=firewalk %s", host);
        }
        break;

    // PORT AND SERVICES SCANS

    // TCP Port scan
    case 12:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sT %s", host);
        }
        break;

    // UDP Port scan
    case 13:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sU %s", host);
        }
        break;

    // Services and version scan
    case 14:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sV %s", host);
        }
        break;

    // Stealth scan
    case 15:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sS %s", host);
        }
        break;

    // Banner grabbing scan nmap -sV --script=banner <host>
    case 16:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sV --script=banner %s", host);
        }
        break;

    // Idle scan (zombie) nmap -sI <zombie host> <target>
    case 17:
        {
            char host[100];
            char zombiehost[100];
            printf("\nEnter the zombie host IP: ");
            scanf("%s", zombiehost);
            printf("\nEnter the target IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sI %s %s", zombiehost, host);
        }
        break;

    // SCTP Init scan, nmap -sY <host>
    case 18:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sY %s", host);
        }
        break;

    // SCTP COOKIE-ECHO Scan, nmap -sZ <host>
    case 19:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sZ %s", host);
        }
        break;

    // AGRESSIVE SCANS

    // Agressive scan
    case 20:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -T4 -A -v %s", host);
        }
        break;

    // Full agressive scan, nmap -A <host>
    case 21:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -A %s", host);
        }
        break;

    // SCRIPTED SCANS

    // HTTP enumeration scan, nmap --script=http-enum <target>
    case 22:
        {
            char target[100];
            printf("\nEnter the target IP or domain name: ");
            scanf("%s", target);
            sprintf(command, "nmap -A %s", target);
        }
        break;

    // SMB OS Discovery, nmap --script=smb-os-discovery <target>
    case 23:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --script=smb-os-discovery %s", host);
        }
        break;

    // DNS Brute Force scan, nmap --script=dns-brute <target>
    case 24:
        {
            char target[100];
            printf("\nEnter the target IP or domain name: ");
            scanf("%s", target);
            sprintf(command, "nmap --script=dns-brute %s", target);
        }
        break;

    // DNS zone transfer scan, nmap --script=dns-zone-transfer <target>
    case 25:
        {
            char target[100];
            printf("\nEnter the target IP or domain name: ");
            scanf("%s", target);
            sprintf(command, "nmap --script=dns-zone-transfer %s", target);
        }
        break;

    // FTP Anonymous login, nmap --script=ftp-anon <target>
    case 26:
        {
            char target[100];
            printf("\nEnter the target IP or domain name: ");
            scanf("%s", target);
            sprintf(command, "nmap --script=ftp-anon %s", target);
        }
        break;

    // SNMP Information scan, nmap -sU -p <port> --script=snmp-info <host>
    case 27:
        {
            char host[100];
            char port[50];
            printf("\nEnter the port to scan (by default SNMP uses the 161 port): ");
            scanf("%49s", port); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the device IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap -sU -p %s --script=snmp-info %s", port, host);
        }
        break;

    // SSL/TLS scan, nmap --script=ssl-cert,ssl-enum-ciphers <host>
    case 28:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --script=ssl-cert,ssl-enum-ciphers %s", host);
        }
        break;

    // NTP monlist, nmap -sU -p 123 --script=ntp-monlist <host>
    case 29:
        {
            char host[100];
            char port[50];
            printf("\nEnter the port to scan (by default NTP uses the 123 port): ");
            scanf("%49s", port); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the device IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap -sU -p %s --script=ntp-monlist %s", port, host);
        }
        break;

    // SMB Vulnerability scna, nmap --script=smb-vuln-* <host>
    case 30:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --script=smb-vuln-* %s", host);
        }
        break;

    // EVASION AND FRAGMENTATION SCANS

    // Fragmentation scan, nmap -f <host>
    case 31:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -f %s", host);
        }
        break;

    // FTP Bounce scan, nmap -b <ftp relay host> <target>
    case 32:
        {
            char ftp_relay_host[100];
            char target_host[100];
            printf("\nEnter the FTP relay host: ");
            scanf("%99s", ftp_relay_host); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the target device IP: ");
            scanf("%99s", target_host); // Limit input to avoid overflow
            sprintf(command, "nmap -b %s %s", ftp_relay_host, target_host);
        }
        break;

    // Decoy scan, nmap -D RND:10 <host>
    case 33:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -D RND:10 %s", host);
        }
        break;

    // Randomize host order scan, nmap --randomize-hosts <host>
    case 34:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --randomize-hosts %s", host);
        }
        break;

    // Slow scan, nmap -T0 <host>
    case 35:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -T0 %s", host);
        }
        break;

    // MAC address spoofing, nmap --spoof-mac <mac address or vendor name> <host>
    case 36:
        {
            char mac[50];
            char host[100];
            printf("\nEnter the MAC address or vendor name to spoof: ");
            scanf("%49s", mac); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the device IP or host IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap --spoof-mac %s %s", mac, host);
        }
        break;

    // Bad TCP Checksum scan, nmap --badsum <host>
    case 37:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap --badsum %s", host);
        }
        break;

    // IP Protocol scan, nmap -sO <host>
    case 38:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -sO %s", host);
        }
        break;

    // SPECIFIC PURPOSE SCANS

    // IPv6 scan, nmap -6 <host>
    case 39:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -6 %s", host);
        }
        break;

    // Timing templates, nmap -T<0-5> <host>
    case 41:
        {
            char host[100];
            printf("\nEnter the host IP or hostname: ");
            scanf("%s", host);
            sprintf(command, "nmap -T<0-5> %s", host);
        }
        break;

    // SAVING RESULTS

    // Save results in XML, nmap -oX resultado.xml <host>

    case 42:
        {
            char filename[100];
            char host[100];
            printf("\nEnter the filename for XML output: ");
            scanf("%99s", filename); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the host IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap -oX %s.xml %s", filename, host);
        }
        break;

    // Save results in normal text (.txt), nmap -oN resultado.txt <host>

    case 43:
        {
            char filename[100];
            char host[100];
            printf("\nEnter the filename for TXT output: ");
            scanf("%99s", filename); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the host IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap -oN %s.txt %s", filename, host);
        }
        break;
    // Save results in grepable format, nmap -oG resultado.gnmap <host>

    case 44:
        {
            char filename[100];
            char host[100];
            printf("\nEnter the filename for GNMAP output: ");
            scanf("%99s", filename); // Limit input to avoid overflow
            getchar(); // Consume the newline character left by scanf
            printf("\nEnter the device IP: ");
            scanf("%99s", host); // Limit input to avoid overflow
            sprintf(command, "nmap -oG %s.gnmap %s", filename, host);
        }
        break;

    default:
        return;
    }

    printf("\nExecuting scanner number %d", scanNumber);
    printf("\nCommand: %s", command);
    printf("\n-------------------------------------------\n");
    system(command);

    while (getchar() != '\n');
}

int main() {
    showBanner();
    showMenu();

    char input[10];
    int scanNumber;
    
    while (1) {
        printf("\nEnter the scan number to execute or type 'info <number>' for description: ");
        fgets(input, sizeof(input), stdin);

        if (strncmp(input, "info", 4) == 0) {
            sscanf(input, "info %d", &scanNumber);
            showScanInfo(scanNumber);
        } else {
            scanNumber = atoi(input);
            if (scanNumber >= 1 && scanNumber <= 44) {
                executeScan(scanNumber);
            } else if (scanNumber == 45) {
                showMenu();
            } else if (scanNumber == 46) {
                printf("\nFarewell, my old friend. The Abyss always awaits...\n\n");
                break;
                return 0;
            } else {
                printf("Invalid input.\n");
            }
        }
    }

    return 0;
}
