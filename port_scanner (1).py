import socket
import threading
import logging
import argparse
import sys
from datetime import datetime
from queue import Queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler("scan_results.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

results: dict = {}
results_lock = threading.Lock()
port_queue: Queue = Queue()


def resolve_host(host: str) -> str:
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as e:
        logger.error(f"Cannot resolve host '{host}': {e}")
        sys.exit(1)


def scan_port(host: str, port: int, timeout: float) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            code = s.connect_ex((host, port))
            status = "OPEN" if code == 0 else "CLOSED"
    except socket.timeout:
        status = "TIMEOUT"
    except OSError as e:
        status = f"ERROR({e})"

    service = COMMON_PORTS.get(port, "")
    label = f"{port}/tcp  {status:<8}  {service}"

    with results_lock:
        results[port] = status
        if status == "OPEN":
            logger.info(f"  [OPEN]    {label}")
        elif status == "TIMEOUT":
            logger.debug(f"  [TIMEOUT] {label}")
        else:
            logger.debug(f"  [CLOSED]  {label}")


def worker(host: str, timeout: float) -> None:
    while True:
        port = port_queue.get()
        if port is None:
            break
        scan_port(host, port, timeout)
        port_queue.task_done()


def run_scan(host, start_port, end_port, threads, timeout):
    ip = resolve_host(host)
    port_range = range(start_port, end_port + 1)
    total = len(port_range)

    banner = (
        f"\n{'='*55}\n"
        f"  TCP Port Scanner\n"
        f"  Target : {host} ({ip})\n"
        f"  Ports  : {start_port} - {end_port}  ({total} total)\n"
        f"  Threads: {threads}   Timeout: {timeout}s\n"
        f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{'='*55}\n"
    )
    print(banner)

    for port in port_range:
        port_queue.put(port)
    for _ in range(threads):
        port_queue.put(None)

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(ip, timeout), daemon=True)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()

    open_ports    = [p for p, s in results.items() if s == "OPEN"]
    closed_ports  = [p for p, s in results.items() if s == "CLOSED"]
    timeout_ports = [p for p, s in results.items() if s == "TIMEOUT"]

    summary = (
        f"\n{'='*55}\n"
        f"  Scan Complete  -  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"  Open   : {len(open_ports)}\n"
        f"  Closed : {len(closed_ports)}\n"
        f"  Timeout: {len(timeout_ports)}\n"
    )
    if open_ports:
        summary += f"\n  Open ports:\n"
        for p in sorted(open_ports):
            svc = COMMON_PORTS.get(p, "unknown")
            summary += f"    >> {p}/tcp  ({svc})\n"
    summary += f"{'='*55}\n"
    print(summary)
    logger.info(summary)
    print("Full results saved to scan_results.log")


def parse_args():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-s", "--start-port", type=int, default=1)
    parser.add_argument("-e", "--end-port",   type=int, default=1024)
    parser.add_argument("-p", "--port",        type=int)
    parser.add_argument("-t", "--threads",     type=int, default=100)
    parser.add_argument("--timeout",           type=float, default=1.0)
    parser.add_argument("-v", "--verbose",     action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    start = args.port if args.port else args.start_port
    end   = args.port if args.port else args.end_port
    if start < 1 or end > 65535 or start > end:
        logger.error("Port range must be 1-65535 and start <= end.")
        sys.exit(1)
    run_scan(args.host, start, end, args.threads, args.timeout)


if __name__ == "__main__":
    main()
