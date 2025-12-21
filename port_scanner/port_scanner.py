'''WARNING: DON'T USE FOR ANYTHING - ~12 minutes to scan (65535 ports) and output text'''
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
import os
import argparse

# Optional mapping of known ports to services
KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB"
}

def parse_args():
    '''Arguments - ip address and number of ports'''
    parser = argparse.ArgumentParser(
        description="Async port scanner"
    )

    parser.add_argument(
        "ip",
        nargs="?",
        default="",
        help="Target IP address (default blank)"
    )

    parser.add_argument(
        "-p", "--ports",
        type=int,
        default=65535,
        help="Scan ports 1-N (default: 65535)"
    )

    return parser.parse_args()

def check_port(host, port):
    '''Thread-safe port check'''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) # Set a timeout for the connection attempt

    try:
        result = s.connect_ex((host, port))
        if result == 0:
            return port
        return None
    finally:
        s.close()

async def check_ports(ip, ports):
    '''Async wrapper - scan ports'''
    tasks = [
        asyncio.to_thread(check_port, ip, port)
        for port in range(ports)
        ]
    results = await asyncio.gather(*tasks)
    return [p for p in results if p is not None]

async def grab_banner(ip, port, timeout=2):
    '''Async banner grab'''
    try:
        reader, writer = (
            await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        )
        await asyncio.sleep(0.2) #allow banner to arrive
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode(errors="ignore").strip()

    except asyncio.CancelledError:
        raise  # MUST re-raise in async code

    except (
        asyncio.TimeoutError,
        ConnectionRefusedError,
        ConnectionResetError,
        OSError,
    ):
        return None

async def grab_banners(ip, o_ports):
    '''Grab banners for all ports'''
    banner_map = {}
    for port in o_ports:
        banner = await grab_banner(ip, port)
        banner_map[port] = banner
    return banner_map

async def main(ip, ports):
    '''Main async function'''
    loop = asyncio.get_running_loop()
    #getting an amount of workers based on system and set TPE
    workers = min(100, (os.cpu_count() or 1) * 10)
    loop.set_default_executor(ThreadPoolExecutor(workers))

    # Safe printing regardless of how ports are passed
    if isinstance(ports, range):
        print(f"Scanning {ip} for ports {ports.start}-{ports.stop - 1}...")
    else:
        print(f"Scanning {ip} for ports: {ports}")
    o_ports = await check_ports(ip, ports)
    print(f"\nOpen ports found: {o_ports}\n")

    banners = await grab_banners(ip, o_ports)

    #print cleanly
    for port in o_ports:
        service = KNOWN_PORTS.get(port, "Unknown")
        banner = banners.get(port, "")
        print(f"{ip}:{port} ({service}) → {repr(banner)}")


args = parse_args()
num_ports = args.ports
host_name = socket.gethostname()
host_info = socket.gethostbyname_ex(host_name)
host_text, host_alias, host_ip = host_info
current_ip = str(host_ip)
current_ip = current_ip.replace("'", "").replace("[", "").replace("]", "")
print("Host Name: " + str(host_text))
print("Host Alias: " + str(host_alias))
print("Host IP: " + str(current_ip))
open_ports = []


start_time = time.perf_counter()
asyncio.run(main(current_ip, num_ports))
end_time = time.perf_counter()
elapsed_time = end_time - start_time

print(f"Finished in: {elapsed_time:.4f} seconds.")
