// Made by Vladimir Aleksandrov (xaleks03)
// dns-monitor.h
#ifndef DNSMONITOR_H
#define DNSMONITOR_H

#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <linux/if_ether.h>
#include <ctime>
#include <fstream>
#include <set>
#include <unordered_map>
#include <resolv.h>
#include <sstream>
#include <iomanip>
#include <csignal>

// DNS header structure
struct dns_header
{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

// Global handle for pcap
extern pcap_t *handle;

// Signal handler to break pcap loop
void signal_handler(int signal);

// DNSMonitor class declaration
class DNSMonitor
{
private:
    bool verbose;
    std::string interface;
    std::string pcap_file;
    std::string domains_file;
    std::string translations_file;
    std::set<std::string> domains;
    std::unordered_map<std::string, std::set<std::string>> translations;
    std::ofstream domain_out;
    std::ofstream translation_out;

public:
    DNSMonitor(bool v, std::string i, std::string p, std::string d, std::string t);

    void run();

private:
    std::string timestamp(const struct pcap_pkthdr *pkthdr);
    void capture_packets(pcap_t *handle);
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void process_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr);
    void parseAndPrintSection(ns_msg msg, ns_sect section, const std::string &sectionName, bool verbose, bool isQuestion);
    std::string handle_record(const ns_rr &rr, bool verbose, bool question, const std::string &domain, const ns_msg &msg);
    std::string type_int_to_str(const ns_rr &rr);
    void add_domain(const std::string &domain);
    void add_translation(const std::string &domain, const std::string &ip);
};

#endif // DNS_MONITOR_H
