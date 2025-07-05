#!/usr/bin/env python3
"""
V2Ray Config IP Extractor with Cloudflare Detection

This script parses V2Ray proxy configurations and extracts IP addresses.
It supports vmess, vless, hysteria, hysteria2, trojan, shadowsocks, tuic, and juicity protocols.
It also identifies Cloudflare IP addresses and saves them separately.
"""

import argparse
import base64
import json
import re
import socket
import threading
import urllib.parse
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from typing import Set, Optional, List, Tuple

import requests

logs = True

def info_log(message) -> None:
    """Print log message if showLogs is True."""
    if logs:
        print(message)

def log(message) -> None:
    """Print log message"""
    print(message)


def is_valid_ip(address: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ip_address(address)
        return True
    except ValueError:
        return False


def is_ipv4(address: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        IPv4Address(address)
        return True
    except ValueError:
        return False


def is_ipv6(address: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        IPv6Address(address)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False

    # Don't treat IP addresses as domains
    if is_valid_ip(domain):
        return False

    # Basic domain validation
    if domain.endswith('.'):
        domain = domain[:-1]

    # Check for valid characters and structure
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(domain_pattern.match(domain))


def resolve_domain_to_ips(domain: str, timeout: float = 0.3) -> Tuple[List[str], List[str]]:
    """
    Resolve a domain name to IPv4 and IPv6 addresses with timeout.
    Returns tuple of (ipv4_list, ipv6_list).
    """
    ipv4_addresses = []
    ipv6_addresses = []
    result = {'addresses': None, 'error': None}

    def dns_lookup():
        """Perform DNS lookup in a separate thread."""
        try:
            addr_info = socket.getaddrinfo(domain, None)
            result['addresses'] = addr_info
        except Exception as e:
            result['error'] = e

    # Start DNS lookup in a separate thread
    thread = threading.Thread(target=dns_lookup)
    thread.daemon = True
    thread.start()

    # Wait for the thread to complete or timeout
    thread.join(timeout)

    if thread.is_alive():
        # Thread is still running, which means timeout occurred
        info_log(f"Warning: DNS resolution timeout for domain '{domain}' after {timeout} seconds")
        return ipv4_addresses, ipv6_addresses

    if result['error']:
        info_log(f"Warning: Could not resolve domain '{domain}': {result['error']}")
        return ipv4_addresses, ipv6_addresses

    if result['addresses']:
        try:
            for info in result['addresses']:
                family, _, _, _, sockaddr = info
                ip_addr = sockaddr[0]

                # Remove IPv6 scope identifier if present
                if '%' in ip_addr:
                    ip_addr = ip_addr.split('%')[0]

                if family == socket.AF_INET and is_ipv4(ip_addr):
                    if ip_addr not in ipv4_addresses:
                        ipv4_addresses.append(ip_addr)
                elif family == socket.AF_INET6 and is_ipv6(ip_addr):
                    if ip_addr not in ipv6_addresses:
                        ipv6_addresses.append(ip_addr)
        except Exception as e:
            log(f"Warning: Error processing DNS results for domain '{domain}': {e}")

    return ipv4_addresses, ipv6_addresses


def get_cloudflare_ip_ranges() -> List[str]:
    """Fetch extended Cloudflare IP ranges from ircfspace repository."""
    cloudflare_ranges = []

    try:
        # First try to fetch the extended ranges from ircfspace repository
        info_log("Fetching extended Cloudflare IP ranges from ircfspace repository...")
        response = requests.get('https://raw.githubusercontent.com/ircfspace/cf-ip-ranges/main/export.ipv4', timeout=15)
        if response.status_code == 200:
            extended_ranges = response.text.strip().split('\n')
            cloudflare_ranges.extend([r.strip() for r in extended_ranges if r.strip()])
            info_log(f"Fetched {len(cloudflare_ranges)} extended Cloudflare IP ranges")

            # Also fetch official ranges to ensure complete coverage
            try:
                info_log("Fetching official Cloudflare IP ranges for additional coverage...")
                response_v4 = requests.get('https://www.cloudflare.com/ips-v4', timeout=10)
                if response_v4.status_code == 200:
                    official_ranges = response_v4.text.strip().split('\n')
                    # Add official ranges that might not be in extended list
                    for range_str in official_ranges:
                        if range_str.strip() and range_str.strip() not in cloudflare_ranges:
                            cloudflare_ranges.append(range_str.strip())

                # Fetch IPv6 ranges
                response_v6 = requests.get('https://www.cloudflare.com/ips-v6', timeout=10)
                if response_v6.status_code == 200:
                    ipv6_ranges = response_v6.text.strip().split('\n')
                    cloudflare_ranges.extend([r.strip() for r in ipv6_ranges if r.strip()])

                info_log(f"Total Cloudflare IP ranges (extended + official): {len(cloudflare_ranges)}")
            except Exception as e:
                log(f"Warning: Could not fetch official ranges for additional coverage: {e}")

            # Add additional known Cloudflare ranges that might not be in the lists above
            additional_ranges = ['172.66.0.0/22', '91.193.59.0/24', '156.238.19.0/24']
            for range_str in additional_ranges:
                if range_str not in cloudflare_ranges:
                    cloudflare_ranges.append(range_str)
            info_log(f"Added {len(additional_ranges)} additional known Cloudflare ranges")

            return cloudflare_ranges
        else:
            log(f"Failed to fetch extended ranges (status: {response.status_code}), trying official API...")
    except Exception as e:
        log(f"Error fetching extended Cloudflare IP ranges: {e}")
        log("Trying official Cloudflare API...")

    try:
        # Fallback to official Cloudflare API
        response_v4 = requests.get('https://www.cloudflare.com/ips-v4', timeout=10)
        if response_v4.status_code == 200:
            cloudflare_ranges.extend(response_v4.text.strip().split('\n'))

        # Fetch IPv6 ranges
        response_v6 = requests.get('https://www.cloudflare.com/ips-v6', timeout=10)
        if response_v6.status_code == 200:
            cloudflare_ranges.extend(response_v6.text.strip().split('\n'))

        info_log(f"Fetched {len(cloudflare_ranges)} official Cloudflare IP ranges")
        return cloudflare_ranges

    except Exception as e:
        info_log(f"Error fetching official Cloudflare IP ranges: {e}")
        # Fallback to known Cloudflare ranges (as of 2024)
        fallback_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '172.66.0.0/22', '91.193.59.0/24', '156.238.19.0/24'
        ]
        log(f"Using fallback Cloudflare IP ranges ({len(fallback_ranges)} ranges)")
        return fallback_ranges


def is_cloudflare_ip(ip_addr: str, cf_ranges: List[str]) -> bool:
    """Check if an IP address belongs to Cloudflare."""
    try:
        ip_obj = ip_address(ip_addr)
        for range_str in cf_ranges:
            if ip_obj in ip_network(range_str, strict=False):
                return True
        return False
    except Exception:
        return False


def extract_address_from_vmess(vmess_url: str) -> Optional[str]:
    """Extract address (IP or domain) from vmess:// URL."""
    try:
        # Remove vmess:// prefix
        encoded_config = vmess_url.replace('vmess://', '')

        # Decode base64
        decoded_bytes = base64.b64decode(encoded_config + '==')  # Add padding if needed
        config_json = json.loads(decoded_bytes.decode('utf-8'))

        # Extract address
        address = config_json.get('add', '')
        return address if (is_valid_ip(address) or is_valid_domain(address)) else None

    except Exception as e:
        log(f"Error parsing vmess URL: {e}")
        return None


def extract_address_from_url_based(proxy_url: str) -> Optional[str]:
    """Extract address (IP or domain) from URL-based protocols (vless, hysteria2, trojan, ss)."""
    try:
        # Parse the URL
        parsed = urllib.parse.urlparse(proxy_url)

        # Extract hostname
        hostname = parsed.hostname
        if hostname and (is_valid_ip(hostname) or is_valid_domain(hostname)):
            return hostname

        return None

    except Exception as e:
        log(f"Error parsing URL-based proxy: {e}")
        return None


def is_base64_content(content: str) -> bool:
    """Check if content appears to be base64 encoded."""
    try:
        # Remove whitespace and check if it's valid base64
        content = content.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        if not content:
            return False

        # Base64 should be divisible by 4 after padding
        # and contain only valid base64 characters
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', content):
            return False

        # Try to decode
        decoded = base64.b64decode(content + '==')  # Add padding if needed
        decoded_str = decoded.decode('utf-8')

        # Check if decoded content looks like proxy configs
        # (contains common proxy protocol prefixes)
        proxy_indicators = ['vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria://', 'hysteria2://', 'hy2://', 'tuic://', 'juicity://']
        return any(indicator in decoded_str for indicator in proxy_indicators)

    except Exception:
        return False


def extract_ips_from_config(config_file: str, output_file: str, cf_output_file: str, ipv6_output_file: str, cf_ipv6_output_file: str, resolve_domains: bool = True) -> None:
    """Extract IP addresses from V2Ray config file and save to output files."""
    all_ipv4_addresses: Set[str] = set()
    all_ipv6_addresses: Set[str] = set()
    cloudflare_ipv4_addresses: Set[str] = set()
    cloudflare_ipv6_addresses: Set[str] = set()

    # Get Cloudflare IP ranges
    info_log("Fetching Cloudflare IP ranges...")
    cf_ranges = get_cloudflare_ip_ranges()

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Check if the entire file content is base64 encoded
        if is_base64_content(content):
            info_log("Detected base64 encoded config file. Decoding...")
            try:
                # Remove whitespace and decode
                clean_content = content.strip().replace('\n', '').replace('\r', '').replace(' ', '')
                decoded_content = base64.b64decode(clean_content + '==').decode('utf-8')
                lines = decoded_content.splitlines()
                info_log(f"Successfully decoded base64 content into {len(lines)} lines")
            except Exception as e:
                log(f"Error decoding base64 content: {e}")
                log("Treating as plain text file...")
                lines = content.splitlines()
        else:
            info_log("Processing as plain text config file...")
            lines = content.splitlines()

        info_log(f"\nProcessing {len(lines)} proxy configurations...")

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            address_found = None

            if line.startswith('vmess://'):
                address_found = extract_address_from_vmess(line)
            elif line.startswith(('vless://', 'hysteria2://', 'hy2://', 'hysteria://', 'trojan://', 'ss://', 'tuic://', 'juicity://')):
                address_found = extract_address_from_url_based(line)
            else:
                info_log(f"Unknown protocol on line {line_num}: {line[:50]}...")
                continue

            if address_found:
                addresses_to_process = []

                # Check if it's already an IP address
                if is_valid_ip(address_found):
                    addresses_to_process.append(address_found)
                    info_log(f"Found IP: {address_found}")
                # If it's a domain and domain resolution is enabled
                elif is_valid_domain(address_found) and resolve_domains:
                    info_log(f"Found domain: {address_found}, resolving...")
                    ipv4_list, ipv6_list = resolve_domain_to_ips(address_found)
                    addresses_to_process.extend(ipv4_list)
                    addresses_to_process.extend(ipv6_list)
                    if ipv4_list or ipv6_list:
                        info_log(f"  Resolved to: {', '.join(ipv4_list + ipv6_list)}")
                    else:
                        info_log(f"  Could not resolve domain: {address_found}")
                elif is_valid_domain(address_found) and not resolve_domains:
                    info_log(f"Found domain: {address_found} (skipping - domain resolution disabled)")

                # Process all resolved IP addresses
                for ip_addr in addresses_to_process:
                    if is_ipv4(ip_addr):
                        if ip_addr not in all_ipv4_addresses:
                            all_ipv4_addresses.add(ip_addr)

                            # Check if it's a Cloudflare IP
                            if is_cloudflare_ip(ip_addr, cf_ranges):
                                cloudflare_ipv4_addresses.add(ip_addr)
                                info_log(f"Found Cloudflare IPv4: {ip_addr}")
                            else:
                                info_log(f"Other IPv4: {ip_addr}")

                    elif is_ipv6(ip_addr):
                        if ip_addr not in all_ipv6_addresses:
                            all_ipv6_addresses.add(ip_addr)

                            # Check if it's a Cloudflare IP
                            if is_cloudflare_ip(ip_addr, cf_ranges):
                                cloudflare_ipv6_addresses.add(ip_addr)
                                info_log(f"Found Cloudflare IPv6: {ip_addr}")
                            else:
                                info_log(f"Other IPv6: {ip_addr}")

        # Write IPv4 addresses to output file
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(all_ipv4_addresses):
                f.write(f"{ip}\n")

        # Write IPv6 addresses to output file
        with open(ipv6_output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(all_ipv6_addresses):
                f.write(f"{ip}\n")

        # Write Cloudflare IPv4 addresses to separate file
        with open(cf_output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(cloudflare_ipv4_addresses):
                f.write(f"{ip}\n")

        # Write Cloudflare IPv6 addresses to separate file
        with open(cf_ipv6_output_file, 'w', encoding='utf-8') as f:
            for ip in sorted(cloudflare_ipv6_addresses):
                f.write(f"{ip}\n")

        log(f"\n" + "="*60)
        log(f"SUMMARY:")
        log(f"Total unique IPv4 addresses: {len(all_ipv4_addresses)}")
        log(f"Total unique IPv6 addresses: {len(all_ipv6_addresses)}")
        log(f"Cloudflare IPv4 addresses: {len(cloudflare_ipv4_addresses)}")
        log(f"Cloudflare IPv6 addresses: {len(cloudflare_ipv6_addresses)}")
        log(f"Non-Cloudflare IPv4 addresses: {len(all_ipv4_addresses) - len(cloudflare_ipv4_addresses)}")
        log(f"Non-Cloudflare IPv6 addresses: {len(all_ipv6_addresses) - len(cloudflare_ipv6_addresses)}")
        log(f"\nFiles created:")
        log(f"- All IPv4 IPs: {output_file}")
        log(f"- All IPv6 IPs: {ipv6_output_file}")
        log(f"- Cloudflare IPv4 IPs: {cf_output_file}")
        log(f"- Cloudflare IPv6 IPs: {cf_ipv6_output_file}")
        log("="*60)

    except FileNotFoundError:
        log(f"Error: Config file '{config_file}' not found.")
    except Exception as e:
        log(f"Error processing config file: {e}")


def main():
    """Main function."""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="V2Ray Config IP Extractor with Cloudflare Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_ips.py -f config.txt
  python extract_ips.py --file my_proxies.txt
  python extract_ips.py -f config.txt -o my_ipv4.txt --ipv6-output my_ipv6.txt
  python extract_ips.py -f config.txt -c my_cf_ipv4.txt --cloudflare-ipv6 my_cf_ipv6.txt
  python extract_ips.py -f config.txt --no-resolve-domains  # Skip domain resolution
        """
    )

    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Path to the V2Ray config file'
    )

    parser.add_argument(
        '-o', '--output',
        default='extracted_ipv4.txt',
        help='Output file for all IPv4 addresses (default: extracted_ipv4.txt)'
    )

    parser.add_argument(
        '--ipv6-output',
        default='extracted_ipv6.txt',
        help='Output file for all IPv6 addresses (default: extracted_ipv6.txt)'
    )

    parser.add_argument(
        '-c', '--cloudflare',
        default='cloudflare_ipv4.txt',
        help='Output file for Cloudflare IPv4 addresses (default: cloudflare_ipv4.txt)'
    )

    parser.add_argument(
        '--cloudflare-ipv6',
        default='cloudflare_ipv6.txt',
        help='Output file for Cloudflare IPv6 addresses (default: cloudflare_ipv6.txt)'
    )

    parser.add_argument(
        '--no-resolve-domains',
        action='store_true',
        help='Disable domain name resolution (only extract direct IP addresses)'
    )

    # Parse arguments
    args = parser.parse_args()

    config_file = args.file
    output_file = args.output
    ipv6_output_file = args.ipv6_output
    cf_output_file = args.cloudflare
    cf_ipv6_output_file = args.cloudflare_ipv6
    resolve_domains = not args.no_resolve_domains

    log("V2Ray Config IP Extractor with Cloudflare Detection")
    log("=" * 60)
    log(f"Reading from: {config_file}")
    log(f"Writing IPv4 IPs to: {output_file}")
    log(f"Writing IPv6 IPs to: {ipv6_output_file}")
    log(f"Writing Cloudflare IPv4 IPs to: {cf_output_file}")
    log(f"Writing Cloudflare IPv6 IPs to: {cf_ipv6_output_file}")
    log(f"Domain resolution: {'Enabled' if resolve_domains else 'Disabled'}")
    log("\n")

    extract_ips_from_config(config_file, output_file, cf_output_file, ipv6_output_file, cf_ipv6_output_file, resolve_domains)


if __name__ == "__main__":
    main()
