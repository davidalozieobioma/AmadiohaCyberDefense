import re
from rich.console import Console
from rich.table import Table

console = Console()

FAILED_PATTERN = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"


def analyze_log(log_file):
    ip_counts = {}

    try:
        with open(log_file, "r") as f:
            for line in f:
                match = re.search(FAILED_PATTERN, line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except FileNotFoundError:
        console.print(f"[red]Log file not found: {log_file}[/red]")
        return

    return ip_counts


def display_results(ip_counts):
    table = Table(title="Amadioha Cyber Defense — Failed Login Attempts")

    table.add_column("IP Address", style="cyan")
    table.add_column("Attempts", style="magenta")

    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        table.add_row(ip, str(count))

    console.print(table)


if __name__ == "__main__":
    log_path = input("Enter path to auth.log: ")
    results = analyze_log(log_path)

    if results:
        display_results(results)
