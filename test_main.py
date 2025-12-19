#!/usr/bin/env python3
"""
Unit and Integration Tests for SubScraper

Tests cover:
1. Job scheduling and slot management
2. Filter logic for reports
3. API endpoints
4. Thread safety and race conditions
"""

import copy
import json
import os
import pytest
import sqlite3
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import functions from main.py
# We'll need to structure this carefully to avoid running the main script
import sys
sys.path.insert(0, os.path.dirname(__file__))

# Mock global state before importing
with patch('main.ensure_dirs'), \
     patch('main.init_database'), \
     patch('main.migrate_json_to_sqlite'):
    import main


class TestJobScheduling:
    """Tests for job scheduling and slot management"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Save original state
        self.original_running_jobs = main.RUNNING_JOBS.copy()
        self.original_queue = deque(main.JOB_QUEUE)
        self.original_max_jobs = main.MAX_RUNNING_JOBS
        
        # Clear state for tests
        main.RUNNING_JOBS.clear()
        main.JOB_QUEUE.clear()
        main.MAX_RUNNING_JOBS = 2
    
    def teardown_method(self):
        """Restore original state"""
        main.RUNNING_JOBS = self.original_running_jobs
        main.JOB_QUEUE = self.original_queue
        main.MAX_RUNNING_JOBS = self.original_max_jobs
    
    def test_count_active_jobs_locked_empty(self):
        """Test counting active jobs when none are running"""
        with main.JOB_LOCK:
            count = main.count_active_jobs_locked()
        assert count == 0
    
    def test_count_active_jobs_locked_with_jobs(self):
        """Test counting active jobs with running threads"""
        # Create mock threads
        mock_thread1 = Mock()
        mock_thread1.is_alive.return_value = True
        mock_thread2 = Mock()
        mock_thread2.is_alive.return_value = True
        mock_thread3 = Mock()
        mock_thread3.is_alive.return_value = False  # Dead thread
        
        with main.JOB_LOCK:
            main.RUNNING_JOBS['domain1.com'] = {'thread': mock_thread1}
            main.RUNNING_JOBS['domain2.com'] = {'thread': mock_thread2}
            main.RUNNING_JOBS['domain3.com'] = {'thread': mock_thread3}
            count = main.count_active_jobs_locked()
        
        assert count == 2  # Only alive threads count
    
    def test_count_active_jobs_locked_no_thread(self):
        """Test counting when jobs exist but have no thread"""
        with main.JOB_LOCK:
            main.RUNNING_JOBS['domain1.com'] = {'status': 'queued'}
            count = main.count_active_jobs_locked()
        
        assert count == 0
    
    def test_schedule_jobs_respects_max_limit(self):
        """Test that schedule_jobs respects MAX_RUNNING_JOBS limit"""
        main.MAX_RUNNING_JOBS = 1
        
        # Add jobs to queue
        with main.JOB_LOCK:
            main.RUNNING_JOBS['domain1.com'] = {
                'domain': 'domain1.com',
                'thread': None,
                'status': 'queued',
                'wordlist': None,
                'skip_nikto': False,
                'interval': 30
            }
            main.RUNNING_JOBS['domain2.com'] = {
                'domain': 'domain2.com',
                'thread': None,
                'status': 'queued',
                'wordlist': None,
                'skip_nikto': False,
                'interval': 30
            }
            main.JOB_QUEUE.append('domain1.com')
            main.JOB_QUEUE.append('domain2.com')
        
        # Mock _start_job_thread to avoid actually starting threads
        started_jobs = []
        
        def mock_start(job):
            mock_thread = Mock()
            mock_thread.is_alive.return_value = True
            with main.JOB_LOCK:
                job['thread'] = mock_thread
            started_jobs.append(job['domain'])
        
        with patch('main._start_job_thread', side_effect=mock_start):
            main.schedule_jobs()
        
        # Should only start 1 job due to MAX_RUNNING_JOBS = 1
        assert len(started_jobs) == 1
        assert started_jobs[0] == 'domain1.com'
        
        with main.JOB_LOCK:
            assert len(main.JOB_QUEUE) == 1  # Second job still queued
            assert main.JOB_QUEUE[0] == 'domain2.com'
    
    def test_schedule_jobs_starts_multiple_if_slots_available(self):
        """Test that schedule_jobs can start multiple jobs if slots available"""
        main.MAX_RUNNING_JOBS = 3
        
        # Add jobs to queue
        with main.JOB_LOCK:
            for i in range(3):
                domain = f'domain{i}.com'
                main.RUNNING_JOBS[domain] = {
                    'domain': domain,
                    'thread': None,
                    'status': 'queued',
                    'wordlist': None,
                    'skip_nikto': False,
                    'interval': 30
                }
                main.JOB_QUEUE.append(domain)
        
        started_jobs = []
        
        def mock_start(job):
            mock_thread = Mock()
            mock_thread.is_alive.return_value = True
            with main.JOB_LOCK:
                job['thread'] = mock_thread
            started_jobs.append(job['domain'])
        
        with patch('main._start_job_thread', side_effect=mock_start):
            main.schedule_jobs()
        
        # Should start all 3 jobs
        assert len(started_jobs) == 3
        assert set(started_jobs) == {'domain0.com', 'domain1.com', 'domain2.com'}
        
        with main.JOB_LOCK:
            assert len(main.JOB_QUEUE) == 0
    
    def test_schedule_jobs_thread_safety(self):
        """Test that schedule_jobs is thread-safe under concurrent access"""
        main.MAX_RUNNING_JOBS = 2
        
        # Add many jobs to queue
        with main.JOB_LOCK:
            for i in range(10):
                domain = f'domain{i}.com'
                main.RUNNING_JOBS[domain] = {
                    'domain': domain,
                    'thread': None,
                    'status': 'queued',
                    'wordlist': None,
                    'skip_nikto': False,
                    'interval': 30
                }
                main.JOB_QUEUE.append(domain)
        
        started_jobs = []
        start_lock = threading.Lock()
        
        def mock_start(job):
            # Simulate some work
            time.sleep(0.01)
            mock_thread = Mock()
            mock_thread.is_alive.return_value = True
            with main.JOB_LOCK:
                job['thread'] = mock_thread
            with start_lock:
                started_jobs.append(job['domain'])
        
        with patch('main._start_job_thread', side_effect=mock_start):
            # Call schedule_jobs from multiple threads
            threads = []
            for _ in range(5):
                t = threading.Thread(target=main.schedule_jobs)
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
        
        # Should respect MAX_RUNNING_JOBS limit even with concurrent calls
        with main.JOB_LOCK:
            active_count = sum(1 for job in main.RUNNING_JOBS.values()
                             if job.get('thread') and job['thread'].is_alive())
        
        # With MAX_RUNNING_JOBS=2, should have exactly 2 active jobs
        assert active_count == 2
        assert len(started_jobs) == 2
        assert len(set(started_jobs)) == 2  # No duplicates


class TestFilterLogic:
    """Tests for report filtering logic"""
    
    def test_severity_comparison(self):
        """Test severity level comparison"""
        severity_levels = ['NONE', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        # Test that higher severities come after lower ones
        for i, level in enumerate(severity_levels):
            assert severity_levels.index(level) == i
        
        # Test filtering logic
        filter_severity = 'MEDIUM'
        filter_index = severity_levels.index(filter_severity)
        
        # These should pass the filter (>= MEDIUM)
        assert severity_levels.index('MEDIUM') >= filter_index
        assert severity_levels.index('HIGH') >= filter_index
        assert severity_levels.index('CRITICAL') >= filter_index
        
        # These should not pass the filter (< MEDIUM)
        assert severity_levels.index('LOW') < filter_index
        assert severity_levels.index('INFO') < filter_index
        assert severity_levels.index('NONE') < filter_index
    
    def test_domain_search_filter(self):
        """Test domain search filtering"""
        test_cases = [
            ('example.com', 'example', True),
            ('example.com', 'EXAMPLE', True),  # Case insensitive
            ('subdomain.example.com', 'example', True),
            ('example.com', 'test', False),
            ('test.com', 'example', False),
        ]
        
        for domain, search, should_match in test_cases:
            result = search.lower() in domain.lower()
            assert result == should_match, f"Failed for domain={domain}, search={search}"


class TestAPIEndpoints:
    """Integration tests for API endpoints"""
    
    def setup_method(self):
        """Setup test fixtures"""
        # Create temporary data directory
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        
        # Initialize test database
        main.ensure_dirs()
        main.init_database()
    
    def teardown_method(self):
        """Cleanup test fixtures"""
        # Restore original data dir
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = main.DATA_DIR / "recon.db"
        
        # Clean up temp directory
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_build_state_payload_structure(self):
        """Test that build_state_payload returns correct structure"""
        with patch('main.load_state', return_value={'targets': {}, 'last_updated': '2024-01-01'}):
            with patch('main.get_config', return_value={}):
                with patch('main.snapshot_running_jobs', return_value=[]):
                    with patch('main.job_queue_snapshot', return_value=[]):
                        with patch('main.snapshot_workers', return_value={}):
                            with patch('main.list_monitors', return_value=[]):
                                with patch('main.load_completed_jobs', return_value={}):
                                    payload = main.build_state_payload()
        
        # Check required keys
        assert 'last_updated' in payload
        assert 'targets' in payload
        assert 'running_jobs' in payload
        assert 'queued_jobs' in payload
        assert 'config' in payload
        assert 'tools' in payload
        assert 'workers' in payload
        assert 'monitors' in payload
    
    def test_build_state_payload_includes_completed_jobs(self):
        """Test that completed jobs are merged into targets"""
        test_state = {
            'targets': {
                'active.com': {
                    'subdomains': {'sub1.active.com': {}},
                    'flags': {},
                    'options': {}
                }
            },
            'last_updated': '2024-01-01'
        }
        
        test_completed_jobs = {
            'completed.com_123456': {
                'state': {
                    'subdomains': {'sub1.completed.com': {}},
                    'flags': {},
                },
                'options': {},
                'completed_at': '2024-01-01T12:00:00Z'
            }
        }
        
        with patch('main.load_state', return_value=test_state):
            with patch('main.get_config', return_value={}):
                with patch('main.snapshot_running_jobs', return_value=[]):
                    with patch('main.job_queue_snapshot', return_value=[]):
                        with patch('main.snapshot_workers', return_value={}):
                            with patch('main.list_monitors', return_value=[]):
                                with patch('main.load_completed_jobs', return_value=test_completed_jobs):
                                    payload = main.build_state_payload()
        
        # Should have both active and completed domains
        assert 'active.com' in payload['targets']
        assert 'completed.com' in payload['targets']
        assert payload['targets']['completed.com']['from_completed_jobs'] == True
        assert payload['targets']['active.com'].get('from_completed_jobs') != True


class TestDatabaseOperations:
    """Tests for SQLite database operations"""
    
    def setup_method(self):
        """Setup test database"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test.db"
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        
        # Create tables
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                domain TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                flags TEXT,
                options TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(domain, subdomain),
                FOREIGN KEY (domain) REFERENCES targets(domain) ON DELETE CASCADE
            )
        """)
        self.conn.commit()
    
    def teardown_method(self):
        """Cleanup test database"""
        self.conn.close()
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_insert_target(self):
        """Test inserting a target into database"""
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute(
            """INSERT INTO targets 
               (domain, data, flags, options, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            ('example.com', '{}', '{}', '{}', now, now)
        )
        self.conn.commit()
        
        cursor.execute("SELECT * FROM targets WHERE domain = ?", ('example.com',))
        row = cursor.fetchone()
        
        assert row is not None
        assert row['domain'] == 'example.com'
    
    def test_insert_subdomain(self):
        """Test inserting subdomains into database"""
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # First insert target
        cursor.execute(
            """INSERT INTO targets 
               (domain, data, flags, options, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            ('example.com', '{}', '{}', '{}', now, now)
        )
        
        # Then insert subdomain
        sub_data = json.dumps({'sources': ['amass'], 'httpx': {}})
        cursor.execute(
            """INSERT INTO subdomains 
               (domain, subdomain, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?)""",
            ('example.com', 'sub1.example.com', sub_data, now, now)
        )
        self.conn.commit()
        
        cursor.execute("SELECT * FROM subdomains WHERE domain = ?", ('example.com',))
        row = cursor.fetchone()
        
        assert row is not None
        assert row['subdomain'] == 'sub1.example.com'
        
        data = json.loads(row['data'])
        assert 'sources' in data
        assert 'amass' in data['sources']
    
    def test_cascade_delete(self):
        """Test that deleting a target deletes its subdomains"""
        cursor = self.conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        # Insert target and subdomain
        cursor.execute(
            """INSERT INTO targets 
               (domain, data, flags, options, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            ('example.com', '{}', '{}', '{}', now, now)
        )
        cursor.execute(
            """INSERT INTO subdomains 
               (domain, subdomain, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?)""",
            ('example.com', 'sub1.example.com', '{}', now, now)
        )
        self.conn.commit()
        
        # Delete target
        cursor.execute("DELETE FROM targets WHERE domain = ?", ('example.com',))
        self.conn.commit()
        
        # Check subdomain is also deleted
        cursor.execute("SELECT * FROM subdomains WHERE domain = ?", ('example.com',))
        row = cursor.fetchone()
        
        assert row is None


class TestThreadSafety:
    """Tests for thread safety and race conditions"""
    
    def test_job_lock_prevents_race_conditions(self):
        """Test that JOB_LOCK prevents concurrent modifications"""
        main.RUNNING_JOBS.clear()
        counter = {'value': 0}
        errors = []
        
        def increment_with_lock():
            try:
                for _ in range(100):
                    with main.JOB_LOCK:
                        # Simulate some work
                        temp = counter['value']
                        time.sleep(0.0001)  # Small delay to encourage race conditions
                        counter['value'] = temp + 1
            except Exception as e:
                errors.append(e)
        
        # Run from multiple threads
        threads = []
        for _ in range(10):
            t = threading.Thread(target=increment_with_lock)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should be exactly 1000 (10 threads * 100 increments each)
        assert counter['value'] == 1000
        assert len(errors) == 0
    
    def test_tool_gate_limits_concurrent_access(self):
        """Test that ToolGate limits concurrent access"""
        gate = main.ToolGate(2)  # Allow max 2 concurrent
        active_count = {'value': 0, 'max_seen': 0}
        lock = threading.Lock()
        
        def worker():
            with gate:
                with lock:
                    active_count['value'] += 1
                    if active_count['value'] > active_count['max_seen']:
                        active_count['max_seen'] = active_count['value']
                
                time.sleep(0.01)  # Simulate work
                
                with lock:
                    active_count['value'] -= 1
        
        # Run many workers
        threads = []
        for _ in range(20):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Max concurrent should never exceed gate limit
        assert active_count['max_seen'] <= 2
        assert active_count['value'] == 0  # All workers finished


class TestUtilityFunctions:
    """Tests for utility functions"""
    
    def test_is_subdomain_input(self):
        """Test subdomain detection"""
        assert main.is_subdomain_input('sub.example.com') == True
        assert main.is_subdomain_input('deep.sub.example.com') == True
        assert main.is_subdomain_input('example.com') == False
        assert main.is_subdomain_input('com') == False
        assert main.is_subdomain_input('') == False
    
    def test_sanitize_domain_input(self):
        """Test domain input sanitization"""
        assert main._sanitize_domain_input('EXAMPLE.COM') == 'example.com'
        assert main._sanitize_domain_input('  example.com  ') == 'example.com'
        assert main._sanitize_domain_input('example.com\n') == 'example.com'
    
    def test_is_rate_limit_error(self):
        """Test rate limit error detection"""
        from urllib.error import HTTPError
        
        # Test HTTP 429
        error_429 = HTTPError('http://test.com', 429, 'Too Many Requests', {}, None)
        assert main.is_rate_limit_error(error_429) == True
        
        # Test HTTP 503
        error_503 = HTTPError('http://test.com', 503, 'Service Unavailable', {}, None)
        assert main.is_rate_limit_error(error_503) == True
        
        # Test timeout message
        error_timeout = Exception('Connection timed out')
        assert main.is_rate_limit_error(error_timeout) == True
        
        # Test rate limit keyword
        error_rate = Exception('rate limit exceeded')
        assert main.is_rate_limit_error(error_rate) == True
        
        # Test normal error
        error_normal = Exception('Some other error')
        assert main.is_rate_limit_error(error_normal) == False


class TestToolConcurrencyLimits:
    """Tests for tool concurrency limits and gates"""
    
    def test_all_tools_have_gates(self):
        """Test that all tools in TOOLS have corresponding TOOL_GATES"""
        # All tools should have gates
        expected_tools = set(main.TOOLS.keys())
        actual_gates = set(main.TOOL_GATES.keys())
        
        # Check that all expected tools have gates
        assert expected_tools == actual_gates, \
            f"Missing gates: {expected_tools - actual_gates}, Extra gates: {actual_gates - expected_tools}"
    
    def test_all_tools_have_config_settings(self):
        """Test that all tools have max_parallel_* config settings"""
        config = main.default_config()
        
        for tool in main.TOOLS.keys():
            # Convert tool name to config key (e.g., "github-subdomains" -> "max_parallel_github_subdomains")
            config_key = f"max_parallel_{tool.replace('-', '_')}"
            assert config_key in config, f"Missing config setting: {config_key}"
            assert isinstance(config[config_key], int), f"Config {config_key} should be an integer"
            assert config[config_key] >= 1, f"Config {config_key} should be >= 1"
    
    def test_apply_concurrency_limits_updates_gates(self):
        """Test that apply_concurrency_limits properly updates tool gates"""
        # Create test config with custom limits
        test_config = main.default_config()
        test_config['max_parallel_amass'] = 5
        test_config['max_parallel_subfinder'] = 3
        test_config['max_parallel_httpx'] = 7
        
        # Apply limits
        main.apply_concurrency_limits(test_config)
        
        # Verify gates were updated
        assert main.TOOL_GATES['amass'].snapshot()['limit'] == 5
        assert main.TOOL_GATES['subfinder'].snapshot()['limit'] == 3
        assert main.TOOL_GATES['httpx'].snapshot()['limit'] == 7
    
    def test_gate_snapshot_returns_correct_data(self):
        """Test that gate snapshot returns limit and active count"""
        gate = main.ToolGate(3)
        snapshot = gate.snapshot()
        
        assert 'limit' in snapshot
        assert 'active' in snapshot
        assert 'queued' in snapshot
        assert snapshot['limit'] == 3
        assert snapshot['active'] == 0
        assert snapshot['queued'] == 0
        
        # Acquire and check again
        gate.acquire()
        snapshot = gate.snapshot()
        assert snapshot['active'] == 1
        
        gate.release()
        snapshot = gate.snapshot()
        assert snapshot['active'] == 0
        
        # Clean up
        gate.stop_worker()
    
    def test_gate_enqueue_executes_work(self):
        """Test that enqueued work items are executed"""
        gate = main.ToolGate(1)
        results = []
        
        def work_func():
            results.append('executed')
            return 'result'
        
        def result_callback(result):
            results.append(result)
        
        gate.enqueue(work_func, result_callback)
        
        # Wait for execution
        time.sleep(0.5)
        
        assert 'executed' in results
        assert 'result' in results
        
        # Clean up
        gate.stop_worker()
    
    def test_gate_queue_respects_capacity(self):
        """Test that queue doesn't exceed capacity limit"""
        gate = main.ToolGate(2)
        active_count = []
        lock = threading.Lock()
        
        def work_func():
            with lock:
                active_count.append(1)
            time.sleep(0.3)  # Simulate work
            with lock:
                active_count.pop()
            return 'done'
        
        # Enqueue more work than capacity
        for _ in range(5):
            gate.enqueue(work_func)
        
        # Give worker time to start processing
        time.sleep(0.1)
        
        # Check that active count never exceeds limit
        snapshot = gate.snapshot()
        assert snapshot['active'] <= 2
        
        # Wait for all work to complete
        time.sleep(2)
        
        # Clean up
        gate.stop_worker()
    
    def test_gate_handles_errors_in_work(self):
        """Test that errors in work items are handled gracefully"""
        gate = main.ToolGate(1)
        errors = []
        
        def failing_work():
            raise ValueError("Test error")
        
        def error_callback(exc):
            errors.append(str(exc))
        
        gate.enqueue(failing_work, error_callback=error_callback)
        
        # Wait for execution
        time.sleep(0.5)
        
        assert len(errors) == 1
        assert "Test error" in errors[0]
        
        # Gate should still be functional
        snapshot = gate.snapshot()
        assert snapshot['active'] == 0
        
        # Clean up
        gate.stop_worker()
    
    def test_gate_multiple_queued_items(self):
        """Test that multiple items can be queued and processed in order"""
        gate = main.ToolGate(1)
        results = []
        lock = threading.Lock()
        
        def make_work_func(value):
            def work():
                with lock:
                    results.append(value)
                time.sleep(0.1)
                return value
            return work
        
        # Enqueue multiple items
        for i in range(5):
            gate.enqueue(make_work_func(i))
        
        # Wait for all to complete
        time.sleep(1.5)
        
        # All items should have been processed
        assert len(results) == 5
        # Results should contain all values 0-4
        assert set(results) == {0, 1, 2, 3, 4}
        
        # Clean up
        gate.stop_worker()
    
    def test_gate_backward_compatibility_context_manager(self):
        """Test that context manager (with statement) still works"""
        gate = main.ToolGate(2)
        
        results = []
        
        def worker():
            with gate:
                results.append('in_context')
                time.sleep(0.1)
        
        threads = []
        for _ in range(3):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        assert len(results) == 3
        
        # Clean up
        gate.stop_worker()


class TestToolGateQueuing:
    """Integration tests for tool gate queuing mechanism"""
    
    def test_job_can_proceed_when_tool_at_capacity(self):
        """Test that a job can proceed with other tools when one tool is at capacity"""
        gate1 = main.ToolGate(1)
        gate2 = main.ToolGate(1)
        
        results = []
        lock = threading.Lock()
        
        def long_work():
            with lock:
                results.append('tool1_started')
            time.sleep(0.5)
            with lock:
                results.append('tool1_finished')
            return 'tool1_done'
        
        def quick_work():
            with lock:
                results.append('tool2_executed')
            return 'tool2_done'
        
        # Fill tool1 capacity
        gate1.enqueue(long_work)
        
        # Enqueue more work to tool1 (will be queued)
        gate1.enqueue(long_work)
        
        # Execute work on tool2 (should not be blocked)
        gate2.enqueue(quick_work)
        
        # Give time for execution
        time.sleep(0.2)
        
        # Tool2 should have executed quickly
        with lock:
            assert 'tool2_executed' in results
            assert 'tool1_started' in results
        
        # Wait for all work to complete
        time.sleep(1)
        
        # Clean up
        gate1.stop_worker()
        gate2.stop_worker()
    
    def test_multiple_jobs_share_tool_queue(self):
        """Test that multiple jobs can share the same tool queue"""
        gate = main.ToolGate(1)
        
        results = []
        lock = threading.Lock()
        
        def job_work(job_id):
            def work():
                with lock:
                    results.append(f'job_{job_id}')
                time.sleep(0.1)
                return f'job_{job_id}_done'
            return work
        
        # Simulate 3 jobs each trying to use the same tool
        for i in range(3):
            gate.enqueue(job_work(i))
        
        # Wait for all to complete
        time.sleep(1)
        
        # All jobs should have been processed
        with lock:
            assert len(results) == 3
            assert 'job_0' in results
            assert 'job_1' in results
            assert 'job_2' in results
        
        # Clean up
        gate.stop_worker()


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])
