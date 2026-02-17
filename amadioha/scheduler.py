"""Task scheduler for recurring security scans."""

from datetime import datetime
from typing import Dict, List
from amadioha import database, network_scanner, log_analyzer


class ScanScheduler:
    """Manages scheduled security scans."""

    def __init__(self):
        self.schedules = self.load_schedules()

    def load_schedules(self) -> List[Dict]:
        """Load active schedules from database."""
        return database.get_scan_schedules()

    def create_schedule(self, target: str, scan_type: str, schedule_time: str,
                        frequency: str, profile: str = 'balanced') -> int:
        """Create a new scan schedule."""
        schedule_id = database.save_scan_schedule(
            target=target,
            scan_type=scan_type,
            schedule_time=schedule_time,
            frequency=frequency,
            profile=profile
        )
        self.schedules = self.load_schedules()
        return schedule_id

    def should_run_network_scan(self, schedule: Dict) -> bool:
        """Determine if a network scan should run based on schedule."""
        if schedule.get('scan_type') != 'network':
            return False

        last_run = schedule.get('last_run')
        frequency = schedule.get('frequency', 'daily')

        from datetime import datetime
        if not last_run:
            return True

        try:
            last_run_time = datetime.fromisoformat(last_run)
        except BaseException:
            return True

        now = datetime.now()

        if frequency == 'hourly':
            return (now - last_run_time).total_seconds() >= 3600
        elif frequency == 'daily':
            return (now - last_run_time).total_seconds() >= 86400
        elif frequency == 'weekly':
            return (now - last_run_time).total_seconds() >= 604800
        elif frequency == 'monthly':
            return (now - last_run_time).total_seconds() >= 2592000

        return False

    def run_network_scan(self, schedule: Dict) -> Dict:
        """Execute a network scan from schedule."""
        try:
            target = schedule.get('target')
            profile = schedule.get('profile', 'balanced')

            # Parse target (e.g., "192.168.1.0/24" or "192.168.1.1")
            result = network_scanner.scan_network(
                target=target,
                profile=profile
            )

            # Save to database
            database.save_scan(
                target=target,
                start_port=1,
                end_port=65535,
                open_ports=result.get('open_ports', []),
                profile=profile,
                workers=result.get('workers', 0),
                timeout=result.get('timeout', 0)
            )

            return {
                "success": True,
                "schedule_id": schedule.get('id'),
                "target": target,
                "open_ports": len(result.get('open_ports', [])),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"Error running scheduled network scan: {e}")
            return {
                "success": False,
                "schedule_id": schedule.get('id'),
                "error": str(e)
            }

    def run_log_analysis(self, schedule: Dict) -> Dict:
        """Execute a log analysis from schedule."""
        try:
            log_file = schedule.get('target')

            # Run analysis
            result = log_analyzer.analyze_auth_log(log_file)

            # Save to database
            threats = result.get('threats', [])
            database.save_analysis(
                log_file=log_file,
                total_ips=result.get('unique_ips', 0),
                threats=threats
            )

            return {
                "success": True,
                "schedule_id": schedule.get('id'),
                "log_file": log_file,
                "threats_detected": len(threats),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"Error running scheduled log analysis: {e}")
            return {
                "success": False,
                "schedule_id": schedule.get('id'),
                "error": str(e)
            }

    def execute_schedules(self) -> Dict:
        """Execute all active schedules that are due."""
        results = []

        for schedule in self.schedules:
            if not schedule.get('enabled', True):
                continue

            scan_type = schedule.get('scan_type', 'network')

            if scan_type == 'network' and self.should_run_network_scan(schedule):
                result = self.run_network_scan(schedule)
                results.append(result)
            elif scan_type == 'log_analysis' and self.should_run_network_scan(schedule):
                result = self.run_log_analysis(schedule)
                results.append(result)

        return {
            "executed": len(results),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }


def start_background_scheduler():
    """Start background scheduler thread."""
    import threading
    import time

    scheduler = ScanScheduler()

    def scheduler_loop():
        """Run scheduler loop."""
        while True:
            try:
                # Execute schedules every minute
                scheduler.execute_schedules()
                time.sleep(60)
            except Exception as e:
                print(f"Scheduler error: {e}")
                time.sleep(60)

    # Start in background thread
    thread = threading.Thread(target=scheduler_loop, daemon=True)
    thread.start()

    return scheduler


def get_schedule_status() -> Dict:
    """Get status of all schedules."""
    scheduler = ScanScheduler()
    schedules = scheduler.load_schedules()

    return {
        "active_schedules": len(schedules),
        "schedules": schedules,
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    # Test scheduler
    scheduler = ScanScheduler()

    # Create example schedules
    print("Creating example schedules...")
    # Note: This requires actual network_scanner module to be available

    print(f"Active schedules: {len(scheduler.schedules)}")
