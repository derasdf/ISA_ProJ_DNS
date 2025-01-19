// Made by Vladimir Aleksandrov (xaleks03)
// dns-monitor.cpp
#include "dns-monitor.h"

// Session handler
pcap_t *pcap_session = nullptr;

// Stop signal handling
void signal_handler(int signal)
{
    pcap_breakloop(pcap_session);
}

// Monitor constructor
DNSMonitor::DNSMonitor(bool v, std::string i, std::string p, std::string d, std::string t)
    : verbose(v), interface(i), pcap_file(p), domains_file(d), translations_file(t) {}

void DNSMonitor::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open output files if specified
    if (!domains_file.empty())
        domain_out.open(domains_file);
    if (!translations_file.empty())
        translation_out.open(translations_file);

    // Open pcap session
    if (!interface.empty())
    {
        pcap_session = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!pcap_session)
        {
            std::cerr << "Failed to open interface " << interface << ": " << errbuf << std::endl;
            exit(1);
        }
    }
    else if (!pcap_file.empty())
    {
        pcap_session = pcap_open_offline(pcap_file.c_str(), errbuf);
        if (!pcap_session)
        {
            std::cerr << "Failed to open PCAP file " << pcap_file << ": " << errbuf << std::endl;
            exit(1);
        }
    }
    else
    {
        std::cerr << "Error: No interface or PCAP file specified." << std::endl;
        exit(1);
    }

    capture_packets(pcap_session);

    // Close output files
    if (domain_out.is_open())
        domain_out.close();
    if (translation_out.is_open())
        translation_out.close();
}

// Helper func for time in packets
std::string DNSMonitor::timestamp(const struct pcap_pkthdr *pkthdr)
{
    std::time_t timestamp = pkthdr->ts.tv_sec;
    std::tm *ltm = std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(ltm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void DNSMonitor::capture_packets(pcap_t *pcap_session)
{
    // Filter for DNS packets (UDP port 53)
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";

    if (pcap_compile(pcap_session, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Failed to parse filter: " << pcap_geterr(pcap_session) << std::endl;
        exit(1);
    }

    if (pcap_setfilter(pcap_session, &fp) == -1)
    {
        std::cerr << "Failed to install filter: " << pcap_geterr(pcap_session) << std::endl;
        exit(1);
    }

    // Loop through packets with filter
    pcap_loop(pcap_session, 0, packet_handler, reinterpret_cast<u_char *>(this));

    pcap_freecode(&fp);
    pcap_close(pcap_session);
}

// Packet handling
void DNSMonitor::packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    DNSMonitor *monitor = reinterpret_cast<DNSMonitor *>(user_data);
    if (pkthdr->len < 14 + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dns_header))
        return; // Not enough data
    monitor->process_packet(packet, pkthdr);
}

// Process a single DNS packet
void DNSMonitor::process_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr)
{
    // Define headers for IPv4 and IPv6
    struct ip *ip_hdr = (struct ip *)(packet + 14);                                                              // IPv4 header
    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + 14);                                                   // IPv6 header
    struct udphdr *udp_hdr = NULL;                                                                               // UDP header
    struct dns_header *dns_hdr = (struct dns_header *)(packet + 14 + sizeof(struct ip) + sizeof(struct udphdr)); // DNS header
    const u_char *dns_data = NULL;                                                                               // DNS data payload
    int dns_len = 0;                                                                                             // DNS data length

    // Get Ethernet header
    struct ethhdr *eth_hdr = (struct ethhdr *)(packet);

    // Determine if packet is IPv4 or IPv6
    uint16_t ethertype = ntohs(eth_hdr->h_proto);
    if (ethertype == 0x0800) // IPv4
    {
        ip_hdr = (struct ip *)(packet + 14);
        udp_hdr = (struct udphdr *)(packet + 14 + sizeof(struct ip));
        dns_hdr = (struct dns_header *)(packet + 14 + sizeof(struct ip) + sizeof(struct udphdr));
        dns_data = packet + 14 + sizeof(struct ip) + sizeof(struct udphdr);
        dns_len = ntohs(udp_hdr->len) - sizeof(struct udphdr);
    }
    else if (ethertype == 0x86DD) // IPv6
    {
        ip6_hdr = (struct ip6_hdr *)(packet + 14);
        udp_hdr = (struct udphdr *)(packet + 14 + sizeof(struct ip6_hdr));
        dns_hdr = (struct dns_header *)(packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
        dns_data = packet + 14 + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
        dns_len = ntohs(udp_hdr->len) - sizeof(struct udphdr);
    }
    else
    {
        // Unsupported Ethertype
        printf("Unsupported Ethertype: 0x%x\n", ethertype);
        return;
    }

    // Check if DNS data is valid
    if (dns_len <= 0)
        return;

    // Parse DNS data
    ns_msg msg;
    if (ns_initparse(dns_data, dns_len, &msg) < 0)
        return;

    // Get source and destination IP addresses
    std::string src_ip;
    std::string dst_ip;
    if (ethertype == 0x0800) // IPv4
    {
        src_ip = inet_ntoa(ip_hdr->ip_src);
        dst_ip = inet_ntoa(ip_hdr->ip_dst);
    }
    else if (ethertype == 0x86DD) // IPv6
    {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip_str, sizeof(dst_ip_str));
        src_ip = src_ip_str;
        dst_ip = dst_ip_str;
    }

    // Determine if packet is a response
    bool is_response = ns_msg_getflag(msg, ns_f_qr);

    // Print basic packet info if not in verbose mode
    if (!verbose && domains_file.empty() && translations_file.empty())
    {
        std::cout << timestamp(pkthdr) << " " << src_ip << " -> " << dst_ip
                  << (is_response ? " (R " : " (Q ")
                  << ns_msg_count(msg, ns_s_qd) << "/" << ns_msg_count(msg, ns_s_an) << "/"
                  << ns_msg_count(msg, ns_s_ns) << "/" << ns_msg_count(msg, ns_s_ar) << ")\n";
        return;
    }

    // Print detailed packet info if in verbose mode
    if (verbose)
    {
        std::cout << "Timestamp: " << timestamp(pkthdr) << "\n"
                  << "SrcIP: " << src_ip << "\n"
                  << "DstIP: " << dst_ip << "\n"
                  << "SrcPort: " << (udp_hdr->uh_sport == 53 ? "TCP" : "UDP") << "/" << ntohs(udp_hdr->uh_sport) << "\n"
                  << "DstPort: " << (udp_hdr->uh_dport == 53 ? "TCP" : "UDP") << "/" << ntohs(udp_hdr->uh_dport) << "\n"
                  << "Identifier: 0x" << std::hex << ntohs(dns_hdr->id) << std::dec << "\n"
                  << "Flags: QR=" << ns_msg_getflag(msg, ns_f_qr)
                  << ", OPCODE=" << ns_msg_getflag(msg, ns_f_opcode)
                  << ", AA=" << ns_msg_getflag(msg, ns_f_aa)
                  << ", TC=" << ns_msg_getflag(msg, ns_f_tc)
                  << ", RD=" << ns_msg_getflag(msg, ns_f_rd)
                  << ", RA=" << ns_msg_getflag(msg, ns_f_ra)
                  << ", AD=" << ns_msg_getflag(msg, ns_f_ad)
                  << ", CD=" << ns_msg_getflag(msg, ns_f_cd)
                  << ", RCODE=" << ns_msg_getflag(msg, ns_f_rcode) << "\n\n";
    }

    // Parse and print DNS message sections
    if (ns_msg_count(msg, (ns_sect)ns_s_qd) > 0)
        parseAndPrintSection(msg, ns_s_qd, "Question Section", verbose, true);

    if (ns_msg_count(msg, (ns_sect)ns_s_an) > 0)
        parseAndPrintSection(msg, ns_s_an, "Answer Section", verbose, false);

    if (ns_msg_count(msg, (ns_sect)ns_s_ns) > 0)
        parseAndPrintSection(msg, ns_s_ns, "Authority Section", verbose, false);

    if (ns_msg_count(msg, (ns_sect)ns_s_ar) > 0)
        parseAndPrintSection(msg, ns_s_ar, "Additional Section", verbose, false);

    // Print divider if in verbose mode
    if (verbose)
        std::cout << "====================\n";
}

// Parses and prints a DNS message section
void DNSMonitor::parseAndPrintSection(ns_msg msg, ns_sect section, const std::string &sectionName, bool verbose, bool isQuestion)
{
    std::string output; // Store the constructed output for the section

    // Iterate over each record in the section
    for (int i = 0; i < ns_msg_count(msg, section); i++)
    {
        ns_rr rr;
        if (ns_parserr(&msg, section, i, &rr) == 0)
        {
            std::string domain = ns_rr_name(rr);
            output += handle_record(rr, verbose, isQuestion, domain, msg);
        }
    }

    // Print the section if there are valid records
    if (!output.empty())
    {
        if (verbose)
            std::cout << "[" << sectionName << "]\n";
        std::cout << output; // Print the accumulated records
        // Add a newline if necessary
        if ((section == ns_s_qd && (ns_msg_count(msg, ns_s_an) > 0 || ns_msg_count(msg, ns_s_ns) > 0 || ns_msg_count(msg, ns_s_ar) > 1)) ||
            (section == ns_s_an && (ns_msg_count(msg, ns_s_ns) > 0 || ns_msg_count(msg, ns_s_ar) > 1)) ||
            (section == ns_s_ns && ns_msg_count(msg, ns_s_ar) > 1))
        {
            if (verbose)
                std::cout << "\n";
        }
    }
}

// Handles a single DNS record
std::string DNSMonitor::handle_record(const ns_rr &rr, bool verbose, bool question, const std::string &domain, const ns_msg &msg)
{
    std::string output;
    if (verbose && !question)
        output += domain + " " + std::to_string(ns_rr_ttl(rr)) + " IN ";
    else if (verbose && question)
        output += domain + " IN ";

    // Handle different record types
    switch (ns_rr_type(rr))
    {
    case ns_t_a:
    case ns_t_aaaa:
    {
        // Handle A/AAAA records
        char ip_str[INET6_ADDRSTRLEN];
        if (!question)
        {
            inet_ntop(ns_rr_type(rr) == ns_t_a ? AF_INET : AF_INET6, ns_rr_rdata(rr), ip_str, sizeof(ip_str));
            if (verbose)
                output += type_int_to_str(rr) + ip_str + "\n";
            if (!translations_file.empty())
                add_translation(domain, ip_str);
        }
        else if (verbose && question)
            output += type_int_to_str(rr) + "\n";
        if (!domains_file.empty())
            add_domain(domain);
        break;
    }

    case ns_t_ns:
    case ns_t_cname:
    case ns_t_mx:
    case ns_t_soa:
    case ns_t_srv:
    {
        // Handle NS, CNAME, MX, SOA, and SRV records
        const unsigned char *rdata = ns_rr_rdata(rr);
        unsigned char host[NS_MAXDNAME];
        int unpack_offset = (ns_rr_type(rr) == ns_t_mx) ? 2 : (ns_rr_type(rr) == ns_t_srv) ? 6
                                                                                           : 0;
        if (!domains_file.empty())
        {
            add_domain(domain);
        }
        if (verbose && question)
        {
            output += type_int_to_str(rr) + "\n";
        }
        else if (ns_name_unpack(ns_msg_base(msg), ns_msg_end(msg), rdata + unpack_offset, host, sizeof(host)) >= 0)
        {
            char host_str[NS_MAXDNAME];
            if (ns_name_ntop(host, host_str, sizeof(host_str)) >= 0)
            {
                std::string host_domain = host_str;
                if (verbose)
                {
                    output += type_int_to_str(rr) + host_domain + "\n";
                }
                if (!domains_file.empty())
                {
                    add_domain(host_domain);
                }
            }
        }
        break;
    }
    default:
        // Skip any other record types
        return "";
    }

    return output;
}

// Helper function for types
std::string DNSMonitor::type_int_to_str(const ns_rr &rr)
{
    switch (ns_rr_type(rr))
    {
    case ns_t_a:
        return "A ";
    case ns_t_aaaa:
        return "AAAA ";
    case ns_t_ns:
        return "NS ";
    case ns_t_cname:
        return "CNAME ";
    case ns_t_mx:
        return "MX ";
    case ns_t_soa:
        return "SOA ";
    case ns_t_srv:
        return "SRV ";
    default:
        return "";
    }
}

// Adds a domain to the output file
void DNSMonitor::add_domain(const std::string &domain)
{
    if (!domains_file.empty() && domains.insert(domain).second)
    {
        domain_out << domain << std::endl;
        domain_out.flush();
    }
}

// Adds a translation to the output file
void DNSMonitor::add_translation(const std::string &domain, const std::string &ip)
{
    if (!translations_file.empty() && translations[domain].insert(ip).second)
    {
        translation_out << domain << " " << ip << std::endl;
        translation_out.flush();
    }
}

int main(int argc, char *argv[])
{
    bool verbose = false;
    std::string interface;
    std::string pcap_file;
    std::string domains_file;
    std::string translations_file;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-v")
        {
            verbose = true;
        }
        else if (arg == "-i")
        {
            if (i + 1 < argc)
            {
                interface = argv[++i];
            }
            else
            {
                std::cerr << "Error: -i (interface) requires a value." << std::endl;
                return 1;
            }
        }
        else if (arg == "-p")
        {
            if (i + 1 < argc)
            {
                pcap_file = argv[++i];
            }
            else
            {
                std::cerr << "Error: -p (pcap-file) requires a value." << std::endl;
                return 1;
            }
        }
        else if (arg == "-d")
        {
            if (i + 1 < argc)
            {
                domains_file = argv[++i];
            }
            else
            {
                std::cerr << "Error: -d (domains) requires a value." << std::endl;
                return 1;
            }
        }
        else if (arg == "-t")
        {
            if (i + 1 < argc)
            {
                translations_file = argv[++i];
            }
            else
            {
                std::cerr << "Error: -t (translations) requires a value." << std::endl;
                return 1;
            }
        }
        else
        {
            std::cerr << "Error: Unknown argument " << arg << std::endl;
            return 1;
        }
    }

    // Ensure either interface or pcap file is specified
    if (interface.empty() && pcap_file.empty())
    {
        std::cerr << "Error: Need either -i (interface) or -p (pcap)." << std::endl;
        return 1;
    }

    // Run DNSMonitor
    DNSMonitor monitor(verbose, interface, pcap_file, domains_file, translations_file);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGQUIT, signal_handler);

    monitor.run();

    return 0;
}