import argparse
import ipaddress
import math
from tabulate import tabulate

def get_classful_prefixlen(ip_address):
    first_octet = int(ip_address.split('.')[0])
    if 1 <= first_octet <= 126:
        return 8  # Class A
    elif 128 <= first_octet <= 191:
        return 16  # Class B
    elif 192 <= first_octet <= 223:
        return 24  # Class C
    else:
        raise ValueError("IP address is not in Class A, B, or C range.")

def mask_to_cidr(mask):
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))

def calculate_network_info(ip_address, subnet_mask=None):
    if subnet_mask:
        cidr_prefix = mask_to_cidr(subnet_mask)
        ip_network = f"{ip_address}/{cidr_prefix}"
    else:
        ip_network = ip_address

    network = ipaddress.ip_network(ip_network, strict=False)
    network_info = {
        "Network ID": str(network.network_address),
        "Broadcast Address": str(network.broadcast_address),
        "First Usable IP": str(network.network_address + 1) if network.num_addresses > 2 else "N/A",
        "Last Usable IP": str(network.broadcast_address - 1) if network.num_addresses > 2 else "N/A",
        "Valid Host Range": f"{network.network_address + 1} - {network.broadcast_address - 1}" if network.num_addresses > 2 else "N/A"
    }
    return network_info

def calculate_subnetting_info(ip_network):
    network = ipaddress.ip_network(ip_network, strict=False)
    classful_prefixlen = get_classful_prefixlen(str(network.network_address))
    additional_subnet_bits = network.prefixlen - classful_prefixlen
    host_bits = 32 - network.prefixlen
    num_subnets = 2 ** additional_subnet_bits if additional_subnet_bits >= 0 else 1
    hosts_per_subnet = (2 ** host_bits) - 2 if host_bits > 1 else 1

    return {
        "Classful Mask": str(ipaddress.IPv4Network((0, classful_prefixlen)).netmask),
        "Additional Subnet Bits": additional_subnet_bits,
        "Host Bits": host_bits,
        "Number of Subnets": num_subnets,
        "Hosts per Subnet": hosts_per_subnet,
    }

def calculate_required_subnet_mask(ip_network, required_subnets, required_hosts):
    network = ipaddress.ip_network(ip_network, strict=False)
    base_prefixlen = network.prefixlen
    classful_prefixlen = get_classful_prefixlen(str(network.network_address))
    
    subnet_bits = math.ceil(math.log2(required_subnets))
    
    host_bits = math.ceil(math.log2(required_hosts + 2))

    required_prefixlen = classful_prefixlen + subnet_bits

    if (32 - required_prefixlen) < host_bits:
        required_prefixlen = 32 - host_bits

    subnet_mask = str(ipaddress.IPv4Network((0, required_prefixlen)).netmask)

    return {
        "Required Subnet Mask": subnet_mask,
        "Prefix Length": required_prefixlen,
        "Total Subnets": 2 ** subnet_bits,
        "Hosts per Subnet": (2 ** (32 - required_prefixlen)) - 2
    }

def calculate_vlsm(ip_network, host_requirements):
    sorted_hosts = sorted(host_requirements, reverse=True)
    available_network = ipaddress.ip_network(ip_network, strict=False)
    vlsm_info = []
    current_base_ip = available_network.network_address

    for hosts in sorted_hosts:
        required_ips = hosts + 2
        subnet_bits = 32 - math.ceil(math.log2(required_ips))
        subnet = ipaddress.ip_network((current_base_ip, subnet_bits), strict=False)
        vlsm_info.append({
            "Base IP": str(subnet.network_address),
            "Mask": subnet.prefixlen,
            "Host Requirement": hosts,
            "Network ID": str(subnet.network_address),
            "Broadcast Address": str(subnet.broadcast_address),
            "First Usable IP": str(subnet.network_address + 1),
            "Last Usable IP": str(subnet.broadcast_address - 1),
        })
        current_base_ip = subnet.broadcast_address + 1

    return vlsm_info

def display_vlsm_table(vlsm_info):
    headers = ["Network", "Base IP", "Mask", "Host Requirement", "Network ID", "Broadcast Address", "First Usable IP", "Last Usable IP"]
    table = [[index, info["Base IP"], info["Mask"], info["Host Requirement"], info["Network ID"], info["Broadcast Address"], info["First Usable IP"], info["Last Usable IP"]] for index, info in enumerate(vlsm_info)]
    print(tabulate(table, headers=headers, tablefmt="grid"))

def summarize_routes(routes):
    networks = [ipaddress.ip_network(route, strict=False) for route in routes]

    base_network = networks[0]
    for i in range(base_network.prefixlen, 0, -1):
        supernet = base_network.supernet(new_prefix=i)
        if all(network.subnet_of(supernet) for network in networks):
            return f"Summarized Route: {supernet}"
    
    return f"Summarized Route: {base_network}"

def main():
    parser = argparse.ArgumentParser(description="Network Information Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Network Info Command
    parser_info = subparsers.add_parser("info", help="Get network information")
    parser_info.add_argument("ip_address", help="IP address in CIDR notation or decimal mask format (e.g., 192.168.1.15/24 or 192.168.1.15 255.255.255.0)")
    parser_info.add_argument("subnet_mask", nargs='?', help="Optional subnet mask in decimal format (e.g., 255.255.255.0)")

    # Subnetting Info Command
    parser_subnet = subparsers.add_parser("subnetting", help="Get subnetting details")
    parser_subnet.add_argument("ip_network", help="IP network in CIDR notation (e.g., 192.168.1.0/24)")
    
    # Required Subnet Mask Command
    parser_required_mask = subparsers.add_parser("required_mask", help="Determine required subnet mask for specific subnets and hosts")
    parser_required_mask.add_argument("ip_network", help="Base network in CIDR notation (e.g., 172.29.0.0/16)")
    parser_required_mask.add_argument("required_subnets", type=int, help="Number of required subnets")
    parser_required_mask.add_argument("required_hosts", type=int, help="Number of required hosts per subnet")

    # VLSM Command
    parser_vlsm = subparsers.add_parser("vlsm", help="Variable Length Subnet Mask planning")
    parser_vlsm.add_argument("ip_network", help="Base network in CIDR notation (e.g., 192.168.1.0/24)")
    parser_vlsm.add_argument("host_requirements", nargs='+', type=int, help="List of host requirements for each subnet")

    # Route Summarization Command
    parser_summarize = subparsers.add_parser("summarize", help="Summarize multiple routes")
    parser_summarize.add_argument("routes", nargs='+', help="List of IP networks to summarize (e.g., 192.168.1.0/24 192.168.2.0/24)")

    args = parser.parse_args()

    if args.command == "info":
        if args.subnet_mask:
            result = calculate_network_info(args.ip_address, args.subnet_mask)
        else:
            result = calculate_network_info(args.ip_address)
        
        for key, value in result.items():
            print(f"{key}: {value}")
    elif args.command == "subnetting":
        result = calculate_subnetting_info(args.ip_network)
        for key, value in result.items():
            print(f"{key}: {value}")
    elif args.command == "required_mask":
        result = calculate_required_subnet_mask(args.ip_network, args.required_subnets, args.required_hosts)
        for key, value in result.items():
            print(f"{key}: {value}")
    elif args.command == "vlsm":
        vlsm_info = calculate_vlsm(args.ip_network, args.host_requirements)
        display_vlsm_table(vlsm_info)
    elif args.command == "summarize":
        result = summarize_routes(args.routes)
        print(result) 
    else:
        parser.print_help()

if __name__ == "__main__":
    main()