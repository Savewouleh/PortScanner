"""
Port Scanner — A multithreaded TCP port scanner with service detection.

Usage:
    python scanner.py <target>
    python scanner.py <target> -p 1-65535
    python scanner.py <target> -p 22,80,443,8080
    python scanner.py <target> -t 100 --timeout 2
"""

import argparse
import socket
import sys
import threading
import time
from queue import Queue
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 115: "SFTP", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 194: "IRC", 443: "HTTPS", 445: "SMB", 587: "SMTP/TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}


results_lock = threading.Lock()
open_ports: list[dict] = []
scanned_count = 0
count_lock = threading.Lock()


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address. Returns the IP string."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {target}")
        sys.exit(1)


def get_service_name(port: int) -> str:
    """Try to identify the service running on a port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        return banner[:80] if banner else ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def port_scan(ip: str, port: int, timeout: float, grab: bool) -> None:
    """Scan a single TCP port and record the result if open."""
    global scanned_count
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = get_service_name(port)
            banner = grab_banner(ip, port, timeout) if grab else ""
            with results_lock:
                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                })
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    finally:
        with count_lock:
            scanned_count += 1


def worker(ip: str, queue: Queue, timeout: float, grab: bool) -> None:
    """Thread worker: pulls ports from the queue and scans them."""
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except Exception:
            break
        port_scan(ip, port, timeout, grab)
        queue.task_done()


def print_progress(total: int, stop_event: threading.Event) -> None:
    """Display a live progress indicator while scanning."""
    while not stop_event.is_set():
        with count_lock:
            done = scanned_count
        pct = (done / total) * 100
        bar_len = 30
        filled = int(bar_len * done // total)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"\r  [{bar}] {pct:5.1f}%  ({done}/{total} ports)", end="", flush=True)
        if done >= total:
            break
        time.sleep(0.25)
    print()


def parse_ports(port_arg: str) -> list[int]:
    """
    Parse a port specification string.
      '80'        → [80]
      '20-25'     → [20, 21, 22, 23, 24, 25]
      '22,80,443' → [22, 80, 443]
      '20-25,80'  → [20, 21, 22, 23, 24, 25, 80]
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                print(f"[!] Invalid port range: {part}")
                sys.exit(1)
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                print(f"[!] Invalid port: {p}")
                sys.exit(1)
            ports.add(p)
    return sorted(ports)


def print_results(target: str, ip: str, elapsed: float) -> None:
    """Print a formatted results table."""
    sorted_ports = sorted(open_ports, key=lambda x: x["port"])

    print(f"\n{'─' * 60}")
    print(f"  Scan Report for {target} ({ip})")
    print(f"  Scanned at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Scan completed in {elapsed:.2f}s")
    print(f"{'─' * 60}")

    if not sorted_ports:
        print("  No open ports found.")
    else:
        print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'────':<10} {'─────':<10} {'───────':<15} {'──────'}")
        for entry in sorted_ports:
            port_str = f"{entry['port']}/tcp"
            banner = entry["banner"] if entry["banner"] else ""
            print(f"  {port_str:<10} {'open':<10} {entry['service']:<15} {banner}")
        print(f"\n  {len(sorted_ports)} open port(s) found.")

    print(f"{'─' * 60}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A multithreaded TCP port scanner with service detection.",
        epilog="Examples:\n"
               "  python scanner.py scanme.nmap.org\n"
               "  python scanner.py 192.168.1.1 -p 22,80,443\n"
               "  python scanner.py 10.0.0.1 -p 1-65535 -t 200\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port(s) to scan: single (80), range (1-1024), or list (22,80,443). Default: 1-1024",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Skip banner grabbing (faster scans)",
    )

    args = parser.parse_args()

    target = args.target
    ip = resolve_target(target)
    ports = parse_ports(args.ports)
    grab = not args.no_banner

    print(f"\n  PortScanner v1.0")
    print(f"  Target  : {target} ({ip})")
    print(f"  Ports   : {len(ports)} port(s)")
    print(f"  Threads : {args.threads}")
    print(f"  Timeout : {args.timeout}s")
    print(f"  Banner  : {'on' if grab else 'off'}\n")

    queue: Queue = Queue()
    for port in ports:
        queue.put(port)
      
    stop_event = threading.Event()
    progress_thread = threading.Thread(
        target=print_progress, args=(len(ports), stop_event), daemon=True
    )

    start_time = time.time()
    progress_thread.start()

    threads = []
    for _ in range(min(args.threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, queue, args.timeout, grab))
        t.daemon = True
        threads.append(t)

    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n\n  [!] Scan interrupted by user.")
        stop_event.set()
        sys.exit(0)

    stop_event.set()
    elapsed = time.time() - start_time

    print_results(target, ip, elapsed)


if __name__ == "__main__":
    main()