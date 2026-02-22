# PortScanner
This is a multithreaded TCP port scanner written in Python. It probes a target host to discover which network ports are open,what services are running on them, and optionally grabs banners from those services.



# This is how it works: 

1. Resolve target. Converts a hostname to an IP address using DNS.
2. Fill a queue. All specified ports are loaded into a thread safe Queue.
3. Spawn threads. Multiple worker threads pull ports from the queue and attempt a TCP connection to each one.
4. Record open ports. If a connection succeeds (result == 0), the port is marked open, its service is identified, and a banner is grabbed.
5. Display results. A formatted table is printed with port, state, service name, and banner.

Legal note:
 Only scan systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal.
