import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from rich.console import Console

console = Console()


def scan_port(target: str, port: int, timeout: float) -> Optional[int]:
    try:
        conn = socket.create_connection((target, port), timeout=timeout)
        conn.close()
        return port
    except Exception:
        return None


def scan_range_concurrent(
        target: str,
        start: int,
        end: int,
        timeout: float,
        workers: int) -> List[int]:
    console.print(
        f"[bold cyan]Scanning {target} ports {start}-{end} with {workers} workers...[/bold cyan]")
    ports = range(start, end + 1)
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                console.print(f"[green][+][/green] Port {res} is open")
                open_ports.append(res)
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(description="Concurrent network port scanner")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname")
    parser.add_argument("--start", type=int, default=1, help="Start port")
    parser.add_argument("--end", type=int, default=1024, help="End port")
    parser.add_argument(
        "--profile",
        choices=[
            "fast",
            "balanced",
            "safe"],
        default="balanced",
        help="Preconfigured scan profile")
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of threads (overrides profile)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="Connection timeout seconds (overrides profile)")
    parser.add_argument("--out", help="Write open ports to file")
    args = parser.parse_args()

    profiles = {
        "fast": {"workers": 200, "timeout": 0.3},
        "balanced": {"workers": 50, "timeout": 0.2},
        "safe": {"workers": 20, "timeout": 0.5},
    }

    profile = profiles.get(args.profile, profiles["balanced"])
    workers = args.workers if args.workers is not None else profile["workers"]
    timeout = args.timeout if args.timeout is not None else profile["timeout"]

    open_ports = scan_range_concurrent(args.target, args.start, args.end, timeout, workers)
    if args.out:
        try:
            with open(args.out, "w") as fh:
                for p in open_ports:
                    fh.write(f"{p}\n")
            console.print(f"Wrote {len(open_ports)} open ports to {args.out}")
        except Exception as e:
            console.print(f"[red]Failed to write output file: {e}[/red]")


if __name__ == "__main__":
    main()
