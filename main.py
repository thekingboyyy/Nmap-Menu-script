# Nmap Menu Script
import nmap
import os
import sys
import subprocess


def clear():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60 + "\n")


def print_subheader(text):
    """Print a formatted subheader"""
    print(f"\n{text}\n")


def print_error(text):
    """Print an error message"""
    print(f"\n[ERROR] {text}\n")


def print_success(text):
    """Print a success message"""
    print(f"\n[SUCCESS] {text}\n")


def print_info(text):
    """Print an info message"""
    print(f"\n[INFO] {text}\n")


def get_user_input(prompt):
    """Get input from user"""
    return input(prompt)


def wait_for_user():
    """Wait for user to press Enter"""
    input("\nPress Enter to continue...")


def check_nmap_installed():
    """Check if Nmap is installed"""
    clear()
    print_header("Check Nmap Installation")
    
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print_success("Nmap is installed!")
            print(result.stdout)
        else:
            print_error("Nmap is not installed or not found in PATH")
    except FileNotFoundError:
        print_error("Nmap is not installed on this system")
        print_info("Use option 2 to see installation instructions")


def install_nmap():
    """Show installation instructions for Nmap"""
    clear()
    print_header("Install Nmap")
    
    print("Installation instructions:\n")
    print("For Ubuntu/Debian:")
    print("  sudo apt-get update")
    print("  sudo apt-get install nmap\n")
    
    print("For CentOS/RHEL/Fedora:")
    print("  sudo yum install nmap\n")
    
    print("For macOS (using Homebrew):")
    print("  brew install nmap\n")
    
    print("For Windows:")
    print("  Download from https://nmap.org/download.html\n")
    
    print("For Python nmap library:")
    print("  pip install python-nmap")


def nmap_scan_types():
    """Display information about Nmap scan types"""
    clear()
    print_header("Nmap Scan Types")
    
    print("Common Nmap Scan Types:\n")
    print("-sS : TCP SYN scan (stealth scan)")
    print("-sT : TCP connect scan")
    print("-sU : UDP scan")
    print("-sA : TCP ACK scan")
    print("-sW : TCP Window scan")
    print("-sM : TCP Maimon scan")
    print("-sN : TCP Null scan")
    print("-sF : TCP FIN scan")
    print("-sX : TCP Xmas scan")
    print("-sI : Idle scan")
    print("-sY : SCTP INIT scan")
    print("-sZ : SCTP COOKIE ECHO scan")
    print("-sO : IP protocol scan")
    print("-b  : FTP bounce scan")


def nmap_scan_options():
    """Display basic Nmap scan options"""
    clear()
    print_header("Nmap Scan Options")
    
    print("Basic Scan Options:\n")
    print("-p <port ranges> : Scan specified ports")
    print("-F               : Fast mode - scan fewer ports")
    print("-r               : Scan ports consecutively")
    print("--top-ports <n>  : Scan the n most common ports")
    print("-A               : Enable OS detection, version detection, script scanning")
    print("-O               : Enable OS detection")
    print("-sV              : Probe open ports to determine service/version info")
    print("-v               : Increase verbosity level")
    print("-d               : Increase debugging level")
    print("--reason         : Display reason a port is in a particular state")


def nmap_output_formats():
    """Display Nmap output format options"""
    clear()
    print_header("Nmap Output Formats")
    
    print("Output Format Options:\n")
    print("-oN <file> : Normal output")
    print("-oX <file> : XML output")
    print("-oS <file> : Script kiddie output")
    print("-oG <file> : Grepable output")
    print("-oA <base> : Output in all formats")
    print("--append-output : Append to rather than overwrite files")


def perform_nmap_scan():
    """Perform an actual Nmap scan"""
    clear()
    print_header("Perform Nmap Scan")
    
    target = get_user_input("Enter target IP or hostname: ").strip()
    
    if not target:
        print_error("Target cannot be empty!")
        return
    
    print("\nScan Types:")
    print("1. Quick scan (top 100 ports)")
    print("2. Standard scan")
    print("3. Intense scan (all ports)")
    print("4. Ping scan")
    print("5. Custom scan")
    
    scan_choice = get_user_input("\nSelect scan type: ").strip()
    
    try:
        nm = nmap.PortScanner()
        print_info(f"Scanning {target}...")
        
        if scan_choice == "1":
            nm.scan(target, arguments='--top-ports 100')
        elif scan_choice == "2":
            nm.scan(target, arguments='-sV')
        elif scan_choice == "3":
            nm.scan(target, arguments='-p- -sV')
        elif scan_choice == "4":
            nm.scan(target, arguments='-sn')
        elif scan_choice == "5":
            custom_args = get_user_input("Enter custom nmap arguments: ").strip()
            nm.scan(target, arguments=custom_args)
        else:
            print_error("Invalid scan type!")
            return
        
        print_success("Scan completed!")
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port].get('name', 'unknown')
                    print(f"  Port {port}: {state} ({service})")
    
    except Exception as e:
        print_error(f"Scan failed: {e}")


def advanced_nmap_options():
    """Display advanced Nmap options"""
    clear()
    print_header("Advanced Nmap Options")
    
    print("Advanced Options:\n")
    print("--traceroute           : Trace hop path to each host")
    print("--script <script>      : Run specified NSE script")
    print("--script-args <args>   : Provide arguments to scripts")
    print("--osscan-limit         : Limit OS detection to promising targets")
    print("--osscan-guess         : Guess OS more aggressively")
    print("--badsum               : Send packets with a bogus TCP/UDP checksum")
    print("--adler32              : Use deprecated Adler32 instead of CRC32C")
    print("--spoof-mac <mac>      : Spoof MAC address")
    print("--proxies <url1,[url2]>: Relay connections through HTTP/SOCKS4 proxies")


def nmap_scripting_engine_options():
    """Display NSE (Nmap Scripting Engine) options"""
    clear()
    print_header("Nmap Scripting Engine (NSE) Options")
    
    print("NSE Options:\n")
    print("-sC                    : Run default scripts")
    print("--script <category>    : Run scripts in category (e.g., vuln, exploit)")
    print("--script <script-name> : Run specific script")
    print("--script-args <args>   : Pass arguments to scripts")
    print("--script-trace         : Show all data sent and received")
    print("--script-updatedb      : Update script database")
    
    print("\nCommon Script Categories:")
    print("  auth, broadcast, brute, default, discovery, dos")
    print("  exploit, external, fuzzer, intrusive, malware")
    print("  safe, version, vuln")


def nmap_timing_and_performance_options():
    """Display timing and performance options"""
    clear()
    print_header("Nmap Timing and Performance Options")
    
    print("Timing Templates (0-5):\n")
    print("-T0 : Paranoid (very slow, IDS evasion)")
    print("-T1 : Sneaky (slow, IDS evasion)")
    print("-T2 : Polite (slower, less bandwidth)")
    print("-T3 : Normal (default)")
    print("-T4 : Aggressive (faster, assumes fast network)")
    print("-T5 : Insane (very fast, may sacrifice accuracy)")
    
    print("\nPerformance Options:")
    print("--min-hostgroup <size>     : Minimum parallel host scan group")
    print("--max-hostgroup <size>     : Maximum parallel host scan group")
    print("--min-parallelism <number> : Minimum parallel probes")
    print("--max-parallelism <number> : Maximum parallel probes")
    print("--min-rate <number>        : Minimum packets per second")
    print("--max-rate <number>        : Maximum packets per second")


def nmap_firewall_evasion_techniques():
    """Display firewall evasion techniques"""
    clear()
    print_header("Nmap Firewall/IDS Evasion Techniques")
    
    print("Evasion Techniques:\n")
    print("-f                  : Fragment packets")
    print("--mtu <val>         : Fragment packets with given MTU")
    print("-D <decoy1,decoy2>  : Cloak scan with decoys")
    print("-S <IP>             : Spoof source address")
    print("-e <iface>          : Use specified interface")
    print("-g <portnum>        : Use given port number")
    print("--source-port <num> : Use given source port")
    print("--data-length <num> : Append random data to packets")
    print("--ip-options <opts> : Send packets with specified IP options")
    print("--ttl <val>         : Set IP time-to-live field")
    print("--spoof-mac <mac>   : Spoof MAC address")
    print("--badsum            : Send packets with bogus TCP/UDP checksums")


def nmap_output_options():
    """Display detailed output options"""
    clear()
    print_header("Nmap Output Options")
    
    print("Output Options:\n")
    print("-oN <file>      : Normal output to file")
    print("-oX <file>      : XML output to file")
    print("-oS <file>      : ScRipT KIdd13 output to file")
    print("-oG <file>      : Grepable output to file")
    print("-oA <basename>  : Output in all major formats")
    print("--append-output : Append to files instead of overwriting")
    print("--resume <file> : Resume aborted scan")
    print("--stylesheet <path>: XSL stylesheet for XML output")
    print("--webxml        : Reference stylesheet from Nmap.Org")
    print("--no-stylesheet : Prevent associating XSL stylesheet with XML")


def nmap_host_discovery_options():
    """Display host discovery options"""
    clear()
    print_header("Nmap Host Discovery Options")
    
    print("Host Discovery Options:\n")
    print("-sL     : List scan - simply list targets")
    print("-sn     : Ping scan - disable port scan")
    print("-Pn     : Treat all hosts as online - skip host discovery")
    print("-PS     : TCP SYN discovery to given ports")
    print("-PA     : TCP ACK discovery to given ports")
    print("-PU     : UDP discovery to given ports")
    print("-PY     : SCTP discovery to given ports")
    print("-PE/PP/PM : ICMP echo, timestamp, netmask request")
    print("-PO     : IP Protocol Ping")
    print("-n      : Never do DNS resolution")
    print("-R      : Always resolve (default)")
    print("--dns-servers <servers> : Specify custom DNS servers")
    print("--system-dns : Use OS's DNS resolver")


def nmap_port_specification_and_scan_order_options():
    """Display port specification options"""
    clear()
    print_header("Nmap Port Specification and Scan Order")
    
    print("Port Specification:\n")
    print("-p <port ranges>    : Scan specified ports")
    print("-p-                 : Scan all 65535 ports")
    print("-p U:53,T:21-25,80  : Scan UDP port 53 and TCP ports 21-25,80")
    print("-F                  : Fast - scan fewer ports")
    print("--top-ports <n>     : Scan n most common ports")
    print("--port-ratio <ratio>: Scan ports more common than ratio")
    
    print("\nScan Order:")
    print("-r : Scan ports consecutively (not randomized)")
    print("--randomize-hosts : Randomize target host order")


def nmap_service_and_version_detection_options():
    """Display service and version detection options"""
    clear()
    print_header("Nmap Service/Version Detection")
    
    print("Version Detection Options:\n")
    print("-sV                        : Probe open ports for service/version info")
    print("--version-intensity <level>: Set intensity (0-9, default 7)")
    print("--version-light            : Limit to most likely probes (intensity 2)")
    print("--version-all              : Try every single probe (intensity 9)")
    print("--version-trace            : Show detailed version scan activity")


def nmap_os_detection_options():
    """Display OS detection options"""
    clear()
    print_header("Nmap OS Detection")
    
    print("OS Detection Options:\n")
    print("-O               : Enable OS detection")
    print("--osscan-limit   : Limit OS detection to promising targets")
    print("--osscan-guess   : Guess OS more aggressively")
    print("--max-os-tries <num> : Set max number of OS detection tries")


def nmap_miscellaneous_options():
    """Display miscellaneous options"""
    clear()
    print_header("Nmap Miscellaneous Options")
    
    print("Miscellaneous Options:\n")
    print("-6                : Enable IPv6 scanning")
    print("-A                : Enable OS detection, version detection, scripts, traceroute")
    print("--datadir <dir>   : Specify custom Nmap data file location")
    print("--send-eth        : Send using raw ethernet frames")
    print("--send-ip         : Send using IP packets")
    print("--privileged      : Assume user is fully privileged")
    print("--unprivileged    : Assume user lacks raw socket privileges")
    print("-V                : Print version number")
    print("-h                : Print help summary")


def nmap_debugging_and_verbosity_options():
    """Display debugging and verbosity options"""
    clear()
    print_header("Nmap Debugging and Verbosity")
    
    print("Verbosity and Debugging:\n")
    print("-v        : Increase verbosity level (use -vv for more)")
    print("-d        : Increase debugging level (use -dd for more)")
    print("--reason  : Display reason port is in particular state")
    print("--stats-every <time> : Print periodic timing stats")
    print("--packet-trace : Show all packets sent and received")
    print("--open    : Only show open (or possibly open) ports")
    print("--iflist  : Print host interfaces and routes")


def nmap_example_commands():
    """Display example Nmap commands"""
    clear()
    print_header("Nmap Example Commands")
    
    print("Common Examples:\n")
    print("1. Basic scan:")
    print("   nmap 192.168.1.1\n")
    
    print("2. Scan multiple hosts:")
    print("   nmap 192.168.1.1-10\n")
    
    print("3. Scan entire subnet:")
    print("   nmap 192.168.1.0/24\n")
    
    print("4. Scan specific ports:")
    print("   nmap -p 80,443 192.168.1.1\n")
    
    print("5. Scan port range:")
    print("   nmap -p 1-1000 192.168.1.1\n")
    
    print("6. Fast scan:")
    print("   nmap -F 192.168.1.1\n")
    
    print("7. Aggressive scan:")
    print("   nmap -A 192.168.1.1\n")
    
    print("8. Service version detection:")
    print("   nmap -sV 192.168.1.1\n")
    
    print("9. OS detection:")
    print("   nmap -O 192.168.1.1\n")
    
    print("10. Save results:")
    print("    nmap -oA scan_results 192.168.1.1")


def nmap_references_and_documentation():
    """Display references and documentation"""
    clear()
    print_header("Nmap References and Documentation")
    
    print("Official Resources:\n")
    print("Website      : https://nmap.org")
    print("Documentation: https://nmap.org/docs.html")
    print("Book         : https://nmap.org/book/")
    print("Man Page     : https://nmap.org/book/man.html")
    print("NSE Scripts  : https://nmap.org/nsedoc/")
    print("Download     : https://nmap.org/download.html")
    print("GitHub       : https://github.com/nmap/nmap")


def nmap_common_use_cases():
    """Display common use cases"""
    clear()
    print_header("Nmap Common Use Cases")
    
    print("Common Use Cases:\n")
    print("1. Network inventory and asset discovery")
    print("2. Security auditing and penetration testing")
    print("3. Monitoring service uptime")
    print("4. Network troubleshooting")
    print("5. Detecting unauthorized devices")
    print("6. Finding open ports and services")
    print("7. Identifying OS and software versions")
    print("8. Vulnerability assessment")
    print("9. Firewall rule testing")
    print("10. Network mapping and documentation")


def nmap_tips_and_best_practices():
    """Display tips and best practices"""
    clear()
    print_header("Nmap Tips and Best Practices")
    
    print("Tips and Best Practices:\n")
    print("1. Always get permission before scanning networks")
    print("2. Start with less intrusive scans (-sn, -sS)")
    print("3. Use timing templates appropriately (-T2 to -T4)")
    print("4. Save scan results for documentation (-oA)")
    print("5. Use version detection carefully (-sV)")
    print("6. Combine options for comprehensive scans (-A)")
    print("7. Be aware of network load during scans")
    print("8. Use specific port ranges when possible")
    print("9. Review NSE scripts before running them")
    print("10. Keep Nmap updated for latest features")


def nmap_alternatives_and_complementary_tools():
    """Display alternatives and complementary tools"""
    clear()
    print_header("Alternatives and Complementary Tools")
    
    print("Similar Tools:\n")
    print("Masscan    : Fast port scanner")
    print("Zmap       : Internet-wide scanner")
    print("Unicornscan: Distributed port scanner")
    print("Angry IP   : GUI-based scanner")
    print("Netcat     : Network utility")
    print("Hping      : Packet crafting tool")
    print("Wireshark  : Network protocol analyzer")
    print("Metasploit : Penetration testing framework")
    print("Nikto      : Web server scanner")
    print("OpenVAS    : Vulnerability assessment")


def nmap_faq_and_troubleshooting():
    """Display FAQ and troubleshooting"""
    clear()
    print_header("Nmap FAQ and Troubleshooting")
    
    print("Common Issues:\n")
    print("Q: Nmap requires root privileges")
    print("A: Use sudo or run as administrator\n")
    
    print("Q: Scan is very slow")
    print("A: Adjust timing with -T4 or limit ports with -F\n")
    
    print("Q: No results from scan")
    print("A: Check if host is up with -Pn flag\n")
    
    print("Q: Firewall blocking scans")
    print("A: Try different scan types or evasion techniques\n")
    
    print("Q: NSE scripts not working")
    print("A: Update script database with --script-updatedb\n")


def nmap_changelog_and_release_notes():
    """Display changelog information"""
    clear()
    print_header("Nmap Changelog and Release Notes")
    
    print("Recent versions have included:\n")
    print("- Improved IPv6 support")
    print("- Enhanced NSE script library")
    print("- Better OS detection fingerprints")
    print("- Performance optimizations")
    print("- New scan techniques")
    print("- Updated service probes")
    
    print("\nFor detailed changelog:")
    print("https://nmap.org/changelog.html")


def nmap_community_and_support_resources():
    """Display community resources"""
    clear()
    print_header("Nmap Community and Support")
    
    print("Community Resources:\n")
    print("Mailing Lists : https://nmap.org/mailman/listinfo")
    print("IRC Channel   : #nmap on Libera.Chat")
    print("Bug Reports   : https://github.com/nmap/nmap/issues")
    print("Forums        : https://seclists.org/nmap-dev/")
    print("Twitter       : @nmap")
    print("Stack Overflow: Tag 'nmap'")


def nmap_legal_and_ethics_considerations():
    """Display legal and ethical considerations"""
    clear()
    print_header("Legal and Ethics Considerations")
    
    print("IMPORTANT LEGAL NOTICE:\n")
    print("⚠ Only scan networks you own or have explicit permission to scan")
    print("⚠ Unauthorized scanning may be illegal in your jurisdiction")
    print("⚠ Always follow responsible disclosure practices")
    print("⚠ Respect privacy and data protection laws")
    print("⚠ Be aware of your organization's security policies")
    print("⚠ Document all authorized scanning activities")
    
    print("\nEthical Guidelines:")
    print("- Get written permission before scanning")
    print("- Scan only during approved time windows")
    print("- Minimize network impact")
    print("- Report findings responsibly")
    print("- Maintain confidentiality")


def nmap_future_developments_and_roadmap():
    """Display future developments"""
    clear()
    print_header("Nmap Future Developments")
    
    print("Potential Future Enhancements:\n")
    print("- Enhanced IPv6 capabilities")
    print("- Improved performance for large scans")
    print("- Additional NSE scripts")
    print("- Better integration with other tools")
    print("- Enhanced reporting features")
    print("- Machine learning integration")
    
    print("\nStay updated at: https://nmap.org")


def nmap_conclusion_and_summary():
    """Display conclusion and summary"""
    clear()
    print_header("Conclusion and Summary")
    
    print("Nmap Summary:\n")
    print("Nmap is a powerful, versatile network scanning tool used by")
    print("security professionals, system administrators, and network")
    print("engineers worldwide.")
    
    print("\nKey Takeaways:")
    print("✓ Always use Nmap responsibly and legally")
    print("✓ Start with basic scans and progress to advanced")
    print("✓ Document your scan results")
    print("✓ Keep Nmap updated")
    print("✓ Learn and use NSE scripts effectively")
    print("✓ Understand timing and performance options")
    
    print("\nThank you for using this Nmap menu!")


def nmap_main_menu():
    """Return to main menu placeholder"""
    print_info("Returning to main menu...")


def nmap_exit_script():
    """Exit the script"""
    clear()
    print_header("Exiting Nmap Menu")
    print("Thank you for using the Nmap Menu Script!")
    print("Remember to scan responsibly!\n")


def nmap_invalid_option():
    """Handle invalid menu option"""
    print_error("Invalid option! Please select a valid menu item.")


def nmap_menu():
    actions = {
        "1": check_nmap_installed,
        "2": install_nmap,
        "3": nmap_scan_types,
        "4": nmap_scan_options,
        "5": nmap_output_formats,
        "6": perform_nmap_scan,
        "7": advanced_nmap_options,
        "8": nmap_scripting_engine_options,
        "9": nmap_timing_and_performance_options,
        "10": nmap_firewall_evasion_techniques,
        "11": nmap_output_options,
        "12": nmap_host_discovery_options,
        "13": nmap_port_specification_and_scan_order_options,
        "14": nmap_service_and_version_detection_options,
        "15": nmap_os_detection_options,
        "16": nmap_miscellaneous_options,
        "17": nmap_debugging_and_verbosity_options,
        "18": nmap_example_commands,
        "19": nmap_references_and_documentation,
        "20": nmap_common_use_cases,
        "21": nmap_tips_and_best_practices,
        "22": nmap_alternatives_and_complementary_tools,
        "23": nmap_faq_and_troubleshooting,
        "24": nmap_changelog_and_release_notes,
        "25": nmap_community_and_support_resources,
        "26": nmap_legal_and_ethics_considerations,
        "27": nmap_future_developments_and_roadmap,
        "28": nmap_conclusion_and_summary,
        "29": nmap_main_menu,
        "0": nmap_exit_script,
    }

    while True:
        clear()
        print_header("Nmap - Network Mapper")
        print_subheader("Select an option:")
        print("1. Check if Nmap is installed")
        print("2. Install Nmap")
        print("3. Nmap Scan Types")
        print("4. Nmap Scan Options")
        print("5. Nmap Output Formats")
        print("6. Perform Nmap Scan")
        print("7. Advanced Nmap Options")
        print("8. Nmap Scripting Engine Options")
        print("9. Nmap Timing and Performance Options")
        print("10. Nmap Firewall Evasion Techniques")
        print("11. Nmap Output Options")
        print("12. Nmap Host Discovery Options")
        print("13. Nmap Port Specification and Scan Order Options")
        print("14. Nmap Service and Version Detection Options")
        print("15. Nmap OS Detection Options")
        print("16. Nmap Miscellaneous Options")
        print("17. Nmap Debugging and Verbosity Options")
        print("18. Nmap Example Commands")
        print("19. Nmap References and Documentation")
        print("20. Nmap Common Use Cases")
        print("21. Nmap Tips and Best Practices")
        print("22. Nmap Alternatives and Complementary Tools")
        print("23. Nmap FAQ and Troubleshooting")
        print("24. Nmap Changelog and Release Notes")
        print("25. Nmap Community and Support Resources")
        print("26. Nmap Legal and Ethics Considerations")
        print("27. Nmap Future Developments and Roadmap")
        print("28. Conclusion and Summary")
        print("29. Return to Main Menu")
        print("0. Exit")
        choice = get_user_input("Enter your choice: ").strip()

        action = actions.get(choice)
        if action:
            try:
                # Special handling for "29" (return to main menu) and "0" (exit)
                if choice == "29":
                    action()
                    return  # return to caller (main menu)
                if choice == "0":
                    action()
                    sys.exit(0)

                # Normal action
                action()
            except Exception as ex:
                # Surface any unexpected errors and allow the user to continue
                print_error(f"An error occurred: {ex}")
            finally:
                # Pause after action so the user can read output
                wait_for_user()
        else:
            nmap_invalid_option()
            wait_for_user()


# Run the menu if executed directly
if __name__ == "__main__":
    try:
        nmap_menu()
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye!")
        sys.exit(0)