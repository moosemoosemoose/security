# Async Port Scanner

This project is a simple asynchronous TCP port scanner written in Python. It scans a target system for open ports, attempts basic banner grabbing, and maps common ports to known services. The primary goal of the project is learning concurrency, asyncio, and socket programming, not speed or real‑world deployment.

The scanner uses asyncio combined with a thread pool to perform concurrent connection attempts across a large port range. Once open ports are identified, it optionally retrieves service banners to provide additional context about running services.

⚠️ This tool is for educational purposes only. It is not optimized, hardened, or intended for real‑world scanning or offensive security use.

**Features**

* Asynchronous port scanning using asyncio
* Concurrent socket connections via thread pool executor
* Optional scanning of ports 1–N (default: 1–65535)
* Basic banner grabbing for discovered open ports
* Simple service name mapping for common ports
* Execution timing output

**Technologies Used**

* Python 3
* asyncio
* socket
* concurrent.futures
* argparse

**Purpose**

Learning journey to explore:
* Python async programming patterns
* Thread safety with network sockets
* Performance tradeoffs in large‑scale port scanning
* Basic network service identification

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y31R5FVX)