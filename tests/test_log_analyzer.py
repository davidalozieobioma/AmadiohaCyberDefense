from pathlib import Path
from amadioha import log_analyzer


def test_analyze_log_counts():
    sample = Path(__file__).parent.parent / "sample_auth.log"
    assert sample.exists(), "sample_auth.log must exist for test"
    counts = log_analyzer.analyze_log(str(sample))
    # Expected counts in the provided sample file
    assert counts.get("185.220.101.1", 0) == 5
    assert counts.get("203.0.113.45", 0) == 5
    assert counts.get("198.51.100.22", 0) == 3
