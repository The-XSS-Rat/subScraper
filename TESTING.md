# Testing Guide for SubScraper

This document describes how to run the automated tests for SubScraper.

## Prerequisites

Install testing dependencies:

```bash
pip3 install -r requirements.txt
```

## Running Tests

### Run all tests:

```bash
python3 -m pytest test_main.py -v
```

### Run with coverage report:

```bash
python3 -m pytest test_main.py -v --cov=main --cov-report=html
```

### Run specific test class:

```bash
# Test job scheduling only
python3 -m pytest test_main.py::TestJobScheduling -v

# Test filtering logic only
python3 -m pytest test_main.py::TestFilterLogic -v

# Test API endpoints only
python3 -m pytest test_main.py::TestAPIEndpoints -v

# Test workflow functionality only
python3 -m pytest test_main.py::TestWorkflows -v
```

### Run specific test:

```bash
python3 -m pytest test_main.py::TestJobScheduling::test_count_active_jobs_locked_empty -v
```

## Test Coverage

The test suite covers:

### 1. Job Scheduling (`TestJobScheduling`)
- **Job slot management**: Ensures MAX_RUNNING_JOBS is respected
- **Thread safety**: Validates no race conditions in concurrent scheduling
- **Active job counting**: Tests accurate counting of running jobs
- **Queue management**: Verifies proper job queuing and dequeuing

### 2. Filter Logic (`TestFilterLogic`)
- **Severity filtering**: Tests severity level comparisons
- **Domain search**: Validates case-insensitive domain filtering
- **Combined filters**: Ensures multiple filters work together

### 3. API Endpoints (`TestAPIEndpoints`)
- **State payload structure**: Validates API response format
- **Completed jobs merging**: Tests integration of completed scans
- **Data consistency**: Ensures proper data structure in responses

### 4. Database Operations (`TestDatabaseOperations`)
- **CRUD operations**: Tests create, read, update, delete
- **Foreign keys**: Validates cascade deletes
- **Data integrity**: Ensures consistent database state

### 5. Thread Safety (`TestThreadSafety`)
- **Lock mechanisms**: Tests JOB_LOCK prevents race conditions
- **ToolGate limits**: Validates concurrent access control
- **Resource contention**: Ensures proper synchronization

### 6. Utility Functions (`TestUtilityFunctions`)
- **Input validation**: Tests domain and subdomain detection
- **Error detection**: Validates rate limit error identification
- **Data sanitization**: Tests input cleaning and normalization

### 7. Workflow Management (`TestWorkflows`)
- **Default workflow creation**: Ensures default workflow is auto-created
- **Workflow CRUD operations**: Tests create, read, update, delete
- **Default workflow protection**: Validates default cannot be deleted
- **Workflow selection**: Tests workflow assignment to jobs
- **API endpoint structure**: Validates workflow API responses

## Test Results Interpretation

### Success Output
```
test_main.py::TestJobScheduling::test_count_active_jobs_locked_empty PASSED
test_main.py::TestJobScheduling::test_schedule_jobs_respects_max_limit PASSED
...
======================== X passed in Y.YYs ========================
```

### Failure Output
If a test fails, you'll see:
```
test_main.py::TestJobScheduling::test_count_active_jobs_locked_empty FAILED

=========================== FAILURES ===========================
________________________ test_name ____________________________
[detailed error traceback]
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines. Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - run: pip install -r requirements.txt
      - run: pytest test_main.py -v --cov=main
```

## Troubleshooting

### Import Errors
If you see import errors, ensure you're running from the repository root:
```bash
cd /path/to/subScraper
python3 -m pytest test_main.py -v
```

### Database Lock Errors
If you see "database is locked" errors, ensure no other instance of SubScraper is running:
```bash
# Check for running processes
ps aux | grep main.py

# Kill if necessary
pkill -f main.py
```

### Thread Timeout Errors
Some tests involve threading and may occasionally timeout on slow systems. Increase timeout:
```bash
python3 -m pytest test_main.py -v --timeout=60
```

## Adding New Tests

When adding new features, follow these guidelines:

1. **Create a new test class** for each major feature
2. **Use setup_method** to initialize test state
3. **Use teardown_method** to clean up
4. **Mock external dependencies** (network, filesystem, etc.)
5. **Test edge cases** (empty input, invalid data, race conditions)
6. **Document test purpose** with clear docstrings

Example:
```python
class TestNewFeature:
    """Tests for the new feature"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.original_state = save_state()
    
    def teardown_method(self):
        """Restore original state"""
        restore_state(self.original_state)
    
    def test_basic_functionality(self):
        """Test that basic feature works"""
        result = new_feature_function()
        assert result == expected_value
```

## Performance Testing

For performance-critical code, use pytest-benchmark:

```bash
pip install pytest-benchmark
```

Example benchmark test:
```python
def test_scheduling_performance(benchmark):
    """Benchmark job scheduling speed"""
    result = benchmark(main.schedule_jobs)
    assert result is not None
```

## Code Coverage Goals

Aim for:
- **Overall coverage**: >80%
- **Critical paths** (job scheduling, thread safety): >95%
- **API endpoints**: >90%
- **Utility functions**: >85%

View coverage report:
```bash
python3 -m pytest test_main.py --cov=main --cov-report=html
open htmlcov/index.html
```
