#WARNING: DON'T USE FOR ANYTHING, JUST LEARN
#Should take roughly 12 minutes to scan a system and output text
import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor
import sys
import errno
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

#args
def parse_args():
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
        default=155,
        help="Scan ports 1-N (default: 155)"
    )

    return parser.parse_args()

#Thread-safe port check
def check_port(host, port):
    # Create a new socket for each connection attempt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) # Set a timeout for the connection attempt

    try:
        result = s.connect_ex((host, port))
        if result == 0:
            return port
        return None
    finally:
        s.close()
   
#Async wrapper - scan ports
async def checkPorts(currentIP, numPorts):
    tasks = [
        asyncio.to_thread(check_port, currentIP, port)
        for port in range(numPorts)
        ]
    
    results = await asyncio.gather(*tasks)
    return [p for p in results if p is not None]

#Async banner grab   
async def grabBanner(ip, port, timeout=2):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout                                    )
        await asyncio.sleep(0.2) #allow banner to arrive
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode(errors="ignore").strip()
    except Exception:
        return None

#Grab banners for all ports
async def grabBanners(ip, openPorts):
        banner_map = {}
        for port in openPorts:
            banner = await grabBanner(ip, port)
            banner_map[port] = banner
        return banner_map

#Main async function
async def main(currentIP, numPorts):
    loop = asyncio.get_running_loop() 
    #getting an amount of workers based on system and set TPE
    workers = min(100, (os.cpu_count() or 1) * 10)
    loop.set_default_executor(ThreadPoolExecutor(workers))
    
    # Safe printing regardless of how ports are passed
    if isinstance(numPorts, range):
        print(f"Scanning {currentIP} for ports {numPorts.start}-{numPorts.stop - 1}...")
    else:
        print(f"Scanning {currentIP} for ports: {numPorts}")
    openPorts = await checkPorts(currentIP, numPorts)
    print(f"\nOpen ports found: {openPorts}\n")
    
    banners = await grabBanners(currentIP, openPorts)

    #print cleanly
    for port in openPorts:
        service = KNOWN_PORTS.get(port, "Unknown")
        banner = banners.get(port, "")
        print(f"{currentIP}:{port} ({service}) → {repr(banner)}")


args = parse_args() 
numPorts = args.ports
hostName = socket.gethostname()
hostInfo = socket.gethostbyname_ex(hostName)
hostText, hostAlias, hostIP = hostInfo
currentIP = str(hostIP)
currentIP = currentIP.replace("'", "")
currentIP = currentIP.replace("[", "")
currentIP = currentIP.replace("]", "")
print("Host Name: " + str(hostText))
print("Host Alias: " + str(hostAlias))
print("Host IP: " + str(currentIP))
openPorts = []


startTime = time.perf_counter()
asyncio.run(main(currentIP, numPorts))
endTime = time.perf_counter()
elapsedTime = endTime - startTime

print(f"Finished in: {elapsedTime:.4f} seconds.")
input('Press ENTER to exit')
