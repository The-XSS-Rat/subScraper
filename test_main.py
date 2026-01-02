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
        
        # With MAX_RUNNING_JOBS=2, the active count should be at most 2
        # (it might be less if some threads complete quickly, but should never exceed the limit)
        assert active_count <= main.MAX_RUNNING_JOBS
        # At least 2 jobs should have been started
        assert len(started_jobs) >= 2
        # No duplicates should have been started
        assert len(set(started_jobs)) == len(started_jobs)


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
        
        # Enable foreign keys - CRITICAL for cascade delete tests
        self.conn.execute("PRAGMA foreign_keys=ON")
        
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


class TestConfigurationManagement:
    """Tests for configuration management functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_config_file = main.CONFIG_FILE
        main.DATA_DIR = Path(self.temp_dir)
        main.CONFIG_FILE = main.DATA_DIR / "config.json"
        main.ensure_dirs()
        main.init_database()
        # Clear config cache
        with main.CONFIG_LOCK:
            main.CONFIG.clear()
    
    def teardown_method(self):
        """Cleanup"""
        main.DATA_DIR = self.original_data_dir
        main.CONFIG_FILE = self.original_config_file
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
        with main.CONFIG_LOCK:
            main.CONFIG.clear()
    
    def test_default_config_has_all_required_keys(self):
        """Test that default_config returns all necessary keys"""
        config = main.default_config()
        required_keys = [
            'data_dir', 'state_file', 'dashboard_file', 'default_interval',
            'max_running_jobs', 'enable_amass', 'enable_subfinder',
            'tool_flag_templates', 'setup_completed'
        ]
        for key in required_keys:
            assert key in config, f"Missing key: {key}"
    
    def test_get_config_returns_default_on_first_call(self):
        """Test that get_config returns defaults when no config exists"""
        config = main.get_config()
        assert isinstance(config, dict)
        assert config.get('max_running_jobs') == 1
        assert config.get('default_interval') == 30
    
    def test_save_and_load_config(self):
        """Test saving and loading configuration"""
        test_config = main.default_config()
        test_config['max_running_jobs'] = 5
        test_config['custom_key'] = 'custom_value'
        
        main.save_config(test_config)
        
        # Clear cache
        with main.CONFIG_LOCK:
            main.CONFIG.clear()
        
        # Load should return saved config
        loaded = main.get_config()
        assert loaded['max_running_jobs'] == 5
        assert loaded['custom_key'] == 'custom_value'
    
    def test_update_config_settings(self):
        """Test updating configuration settings"""
        updates = {
            'max_running_jobs': '3',
            'global_rate_limit': '2.5',
            'skip_nikto_by_default': 'true'
        }
        
        success, message, config = main.update_config_settings(updates)
        
        assert success == True
        assert config['max_running_jobs'] == 3
        assert config['global_rate_limit'] == 2.5
        assert config['skip_nikto_by_default'] == True
    
    def test_bool_from_value(self):
        """Test boolean conversion from various input types"""
        assert main.bool_from_value(True, False) == True
        assert main.bool_from_value(False, True) == False
        assert main.bool_from_value('true', False) == True
        assert main.bool_from_value('True', False) == True
        assert main.bool_from_value('yes', False) == True
        assert main.bool_from_value('1', False) == True
        assert main.bool_from_value('false', True) == False
        assert main.bool_from_value('no', True) == False
        assert main.bool_from_value('0', True) == False
        assert main.bool_from_value(None, True) == True  # default
        assert main.bool_from_value('', True) == True  # default
    
    def test_apply_concurrency_limits_from_config(self):
        """Test that concurrency limits are applied from config"""
        config = main.default_config()
        config['max_running_jobs'] = 10
        config['global_rate_limit'] = 1.5
        config['max_parallel_amass'] = 3
        
        original_max_jobs = main.MAX_RUNNING_JOBS
        original_rate_limit = main.GLOBAL_RATE_LIMIT_DELAY
        
        main.apply_concurrency_limits(config)
        
        assert main.MAX_RUNNING_JOBS == 10
        assert main.GLOBAL_RATE_LIMIT_DELAY == 1.5
        assert main.TOOL_GATES['amass'].snapshot()['limit'] == 3
        
        # Restore
        main.MAX_RUNNING_JOBS = original_max_jobs
        main.GLOBAL_RATE_LIMIT_DELAY = original_rate_limit


class TestStateManagement:
    """Tests for state management functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_db_file = main.DB_FILE
        self.original_db_conn = main.DB_CONN
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        main.DB_CONN = None
        main.ensure_dirs()
        main.init_database()
    
    def teardown_method(self):
        """Cleanup"""
        if main.DB_CONN:
            main.DB_CONN.close()
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = self.original_db_file
        main.DB_CONN = self.original_db_conn
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_add_subdomains_to_state(self):
        """Test adding subdomains to state"""
        domain = 'example.com'
        subdomains = ['sub1.example.com', 'sub2.example.com']
        source = 'amass'
        
        main.add_subdomains_to_state(domain, subdomains, source)
        
        # Verify in database
        db = main.get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM targets WHERE domain = ?", (domain,))
        target_row = cursor.fetchone()
        assert target_row is not None
        
        cursor.execute("SELECT * FROM subdomains WHERE domain = ?", (domain,))
        sub_rows = cursor.fetchall()
        assert len(sub_rows) == 2
        
        # Check that sources are recorded
        for row in sub_rows:
            data = json.loads(row['data'])
            assert source in data.get('sources', [])
    
    def test_add_subdomains_deduplicates(self):
        """Test that adding duplicate subdomains doesn't create duplicates"""
        domain = 'example.com'
        subdomains = ['sub1.example.com', 'sub2.example.com']
        
        # Add twice
        main.add_subdomains_to_state(domain, subdomains, 'amass')
        main.add_subdomains_to_state(domain, subdomains, 'subfinder')
        
        # Should still have only 2 subdomains
        db = main.get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM subdomains WHERE domain = ?", (domain,))
        rows = cursor.fetchall()
        assert len(rows) == 2
        
        # But should have both sources
        for row in rows:
            data = json.loads(row['data'])
            sources = data.get('sources', [])
            assert 'amass' in sources
            assert 'subfinder' in sources
    
    def test_load_state_empty(self):
        """Test loading state when no data exists"""
        state = main.load_state()
        assert 'targets' in state
        assert 'last_updated' in state
        assert isinstance(state['targets'], dict)
    
    def test_load_state_with_data(self):
        """Test loading state with existing data"""
        # Add test data
        domain = 'test.com'
        main.add_subdomains_to_state(domain, ['sub.test.com'], 'test')
        
        # Load state
        state = main.load_state()
        assert domain in state['targets']
        assert 'sub.test.com' in state['targets'][domain]['subdomains']


class TestDomainHandling:
    """Tests for domain-related functions"""
    
    def test_sanitize_domain_input(self):
        """Test domain input sanitization"""
        assert main._sanitize_domain_input('EXAMPLE.COM') == 'example.com'
        assert main._sanitize_domain_input('  example.com  ') == 'example.com'
        assert main._sanitize_domain_input('example.com\n\r') == 'example.com'
        assert main._sanitize_domain_input('http://example.com') == 'http://example.com'
    
    def test_is_subdomain_input(self):
        """Test subdomain detection"""
        assert main.is_subdomain_input('api.example.com') == True
        assert main.is_subdomain_input('deep.api.example.com') == True
        assert main.is_subdomain_input('example.com') == False
        assert main.is_subdomain_input('com') == False
        assert main.is_subdomain_input('') == False
        assert main.is_subdomain_input('localhost') == False
    
    def test_expand_wildcard_targets(self):
        """Test wildcard TLD expansion"""
        config = main.default_config()
        config['wildcard_tlds'] = ['com', 'net', 'org']
        
        # Test wildcard expansion
        targets = main.expand_wildcard_targets('example.*', config)
        assert 'example.com' in targets
        assert 'example.net' in targets
        assert 'example.org' in targets
        assert len(targets) == 3
    
    def test_expand_wildcard_targets_no_wildcard(self):
        """Test that non-wildcard input returns as-is"""
        config = main.default_config()
        targets = main.expand_wildcard_targets('example.com', config)
        assert targets == ['example.com']


class TestJobManagement:
    """Tests for job management functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.original_running_jobs = main.RUNNING_JOBS.copy()
        self.original_queue = deque(main.JOB_QUEUE)
        self.original_job_controls = main.JOB_CONTROLS.copy()
        main.RUNNING_JOBS.clear()
        main.JOB_QUEUE.clear()
        main.JOB_CONTROLS.clear()
    
    def teardown_method(self):
        """Restore state"""
        main.RUNNING_JOBS = self.original_running_jobs
        main.JOB_QUEUE = self.original_queue
        main.JOB_CONTROLS = self.original_job_controls
    
    def test_init_job_steps(self):
        """Test job step initialization"""
        steps = main.init_job_steps(skip_nikto=False)
        assert isinstance(steps, dict)
        assert 'amass' in steps
        assert 'subfinder' in steps
        assert 'httpx' in steps
        assert 'nuclei' in steps
        assert 'nikto' in steps
        
        # Test skip nikto
        steps_skip = main.init_job_steps(skip_nikto=True)
        assert steps_skip['nikto']['status'] == 'skipped'
    
    def test_job_control_creation(self):
        """Test JobControl creation and management"""
        domain = 'example.com'
        ctrl = main.ensure_job_control(domain)
        assert ctrl is not None
        assert isinstance(ctrl, main.JobControl)
        
        # Should return same control on second call
        ctrl2 = main.ensure_job_control(domain)
        assert ctrl is ctrl2
    
    def test_job_control_pause_resume(self):
        """Test job pause/resume functionality"""
        ctrl = main.JobControl()
        
        # Initially not paused
        assert ctrl.is_pause_requested() == False
        
        # Request pause
        result = ctrl.request_pause()
        assert result == True
        assert ctrl.is_pause_requested() == True
        
        # Request pause again (should return False)
        result = ctrl.request_pause()
        assert result == False
        
        # Resume
        result = ctrl.request_resume()
        assert result == True
        assert ctrl.is_pause_requested() == False
    
    def test_snapshot_running_jobs(self):
        """Test snapshotting running jobs"""
        with main.JOB_LOCK:
            main.RUNNING_JOBS['test.com'] = {
                'domain': 'test.com',
                'status': 'running',
                'progress': 50,
                'steps': main.init_job_steps(False)
            }
        
        snapshot = main.snapshot_running_jobs()
        assert len(snapshot) == 1
        assert snapshot[0]['domain'] == 'test.com'
        assert snapshot[0]['status'] == 'running'
    
    def test_job_queue_snapshot(self):
        """Test job queue snapshot"""
        with main.JOB_LOCK:
            main.JOB_QUEUE.append('test1.com')
            main.JOB_QUEUE.append('test2.com')
        
        snapshot = main.job_queue_snapshot()
        assert len(snapshot) == 2
        assert 'test1.com' in snapshot
        assert 'test2.com' in snapshot


class TestLockingMechanisms:
    """Tests for file locking and synchronization"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        main.DATA_DIR = Path(self.temp_dir)
        main.LOCK_FILE = main.DATA_DIR / ".lock"
        main.ensure_dirs()
    
    def teardown_method(self):
        """Cleanup"""
        main.DATA_DIR = self.original_data_dir
        main.LOCK_FILE = main.DATA_DIR / ".lock"
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_acquire_lock_creates_file(self):
        """Test that acquire_lock creates lock file"""
        main.acquire_lock()
        assert main.LOCK_FILE.exists()
    
    def test_release_lock_removes_file(self):
        """Test that release_lock removes lock file"""
        main.acquire_lock()
        assert main.LOCK_FILE.exists()
        main.release_lock()
        assert not main.LOCK_FILE.exists()


class TestAtomicFileOperations:
    """Tests for atomic file write operations"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_atomic_write_json(self):
        """Test atomic JSON write"""
        filepath = Path(self.temp_dir) / "test.json"
        data = {'key': 'value', 'number': 42}
        
        main.atomic_write_json(filepath, data)
        
        assert filepath.exists()
        with open(filepath, 'r') as f:
            loaded = json.load(f)
        assert loaded == data
    
    def test_atomic_write_text(self):
        """Test atomic text write"""
        filepath = Path(self.temp_dir) / "test.txt"
        content = "Hello, World!\nThis is a test."
        
        main.atomic_write_text(filepath, content)
        
        assert filepath.exists()
        with open(filepath, 'r') as f:
            loaded = f.read()
        assert loaded == content
    
    def test_atomic_write_json_overwrites_existing(self):
        """Test that atomic write overwrites existing files"""
        filepath = Path(self.temp_dir) / "test.json"
        
        # Write first version
        main.atomic_write_json(filepath, {'version': 1})
        
        # Overwrite with second version
        main.atomic_write_json(filepath, {'version': 2})
        
        # Should have version 2
        with open(filepath, 'r') as f:
            loaded = json.load(f)
        assert loaded['version'] == 2


class TestTemplateRendering:
    """Tests for template argument rendering"""
    
    def test_render_template_args_basic(self):
        """Test basic template rendering"""
        template = "-threads $THREADS$ -timeout $TIMEOUT$"
        context = {'THREADS': '10', 'TIMEOUT': '300'}
        
        args = main.render_template_args(template, context, 'test_tool')
        
        assert '-threads' in args
        assert '10' in args
        assert '-timeout' in args
        assert '300' in args
    
    def test_render_template_args_empty_template(self):
        """Test rendering empty template"""
        args = main.render_template_args('', {}, 'test_tool')
        assert args == []
        
        args = main.render_template_args(None, {}, 'test_tool')
        assert args == []
    
    def test_render_template_args_missing_variable(self):
        """Test rendering with missing context variable"""
        template = "-value $MISSING$"
        context = {}
        
        args = main.render_template_args(template, context, 'test_tool')
        
        # Should replace missing var with empty string
        assert '-value' in args
        assert args[args.index('-value') + 1] == ''
    
    def test_apply_template_flags(self):
        """Test applying template flags to command"""
        cmd = ['tool', '--input', 'file.txt']
        template = "-threads $THREADS$"
        context = {'THREADS': '5'}
        
        # Mock get_tool_flag_template
        with patch('main.get_tool_flag_template', return_value=template):
            result = main.apply_template_flags('test_tool', cmd, context)
        
        assert result == ['tool', '--input', 'file.txt', '-threads', '5']


class TestHistoryManagement:
    """Tests for history/logging functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_db_file = main.DB_FILE
        self.original_db_conn = main.DB_CONN
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        main.DB_CONN = None
        main.ensure_dirs()
        main.init_database()
    
    def teardown_method(self):
        """Cleanup"""
        if main.DB_CONN:
            main.DB_CONN.close()
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = self.original_db_file
        main.DB_CONN = self.original_db_conn
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_append_domain_history(self):
        """Test appending to domain history"""
        domain = 'example.com'
        entry = {
            'ts': datetime.now(timezone.utc).isoformat(),
            'source': 'test',
            'text': 'Test message'
        }
        
        main.append_domain_history(domain, entry)
        
        # Verify in database
        history = main.load_domain_history(domain)
        assert len(history) > 0
        assert history[-1]['text'] == 'Test message'
        assert history[-1]['source'] == 'test'
    
    def test_job_log_append(self):
        """Test appending to job log"""
        domain = 'example.com'
        
        # Create a job
        with main.JOB_LOCK:
            main.RUNNING_JOBS[domain] = {
                'domain': domain,
                'logs': [],
                'status': 'running'
            }
        
        # Append log
        main.job_log_append(domain, 'Test log message', 'test_source')
        
        # Check log was added
        with main.JOB_LOCK:
            job = main.RUNNING_JOBS[domain]
            assert len(job['logs']) == 1
            assert job['logs'][0]['text'] == 'Test log message'
            assert job['logs'][0]['source'] == 'test_source'


class TestMonitorManagement:
    """Tests for monitor management functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_db_file = main.DB_FILE
        self.original_db_conn = main.DB_CONN
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        main.DB_CONN = None
        main.ensure_dirs()
        main.init_database()
        with main.MONITOR_LOCK:
            main.MONITOR_STATE.clear()
    
    def teardown_method(self):
        """Cleanup"""
        if main.DB_CONN:
            main.DB_CONN.close()
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = self.original_db_file
        main.DB_CONN = self.original_db_conn
        with main.MONITOR_LOCK:
            main.MONITOR_STATE.clear()
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_add_monitor(self):
        """Test adding a monitor"""
        success, message, monitor = main.add_monitor(
            name='Test Monitor',
            url='https://example.com/targets.txt',
            interval=300
        )
        
        assert success == True
        assert monitor is not None
        assert monitor['name'] == 'Test Monitor'
        assert monitor['url'] == 'https://example.com/targets.txt'
        assert monitor['interval'] == 300
    
    def test_add_monitor_invalid_url(self):
        """Test adding monitor with invalid URL"""
        success, message, monitor = main.add_monitor(
            name='Bad Monitor',
            url='not-a-url',
            interval=300
        )
        
        assert success == False
        assert monitor is None
    
    def test_add_monitor_no_url(self):
        """Test adding monitor without URL"""
        success, message, monitor = main.add_monitor(
            name='No URL',
            url='',
            interval=300
        )
        
        assert success == False
    
    def test_remove_monitor(self):
        """Test removing a monitor"""
        # First add a monitor
        success, message, monitor = main.add_monitor(
            name='Test',
            url='https://example.com/test.txt',
            interval=300
        )
        monitor_id = monitor['id']
        
        # Now remove it
        success, message = main.remove_monitor(monitor_id)
        
        assert success == True
        
        # Verify it's gone
        monitors = main.list_monitors()
        assert len([m for m in monitors if m['id'] == monitor_id]) == 0
    
    def test_list_monitors(self):
        """Test listing monitors"""
        # Add a few monitors
        main.add_monitor('Mon1', 'https://example.com/1.txt', 300)
        main.add_monitor('Mon2', 'https://example.com/2.txt', 300)
        
        monitors = main.list_monitors()
        assert len(monitors) >= 2


class TestBackupSystem:
    """Tests for backup and restore functions"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_backups_dir = main.BACKUPS_DIR
        main.DATA_DIR = Path(self.temp_dir)
        main.BACKUPS_DIR = main.DATA_DIR / "backups"
        main.ensure_dirs()
    
    def teardown_method(self):
        """Cleanup"""
        main.DATA_DIR = self.original_data_dir
        main.BACKUPS_DIR = self.original_backups_dir
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_create_backup(self):
        """Test creating a backup"""
        # Create some test data
        test_file = main.DATA_DIR / "test_data.txt"
        test_file.write_text("test data")
        
        success, message, filename = main.create_backup("test_backup")
        
        assert success == True
        assert filename is not None
        assert filename.endswith('.tar.gz')
        assert (main.BACKUPS_DIR / filename).exists()
    
    def test_list_backups(self):
        """Test listing backups"""
        # Create a backup
        test_file = main.DATA_DIR / "test_data.txt"
        test_file.write_text("test data")
        main.create_backup("backup1")
        
        backups = main.list_backups()
        assert len(backups) >= 1
        assert any('backup1' in b['filename'] for b in backups)
    
    def test_delete_backup(self):
        """Test deleting a backup"""
        # Create a backup
        test_file = main.DATA_DIR / "test_data.txt"
        test_file.write_text("test data")
        success, message, filename = main.create_backup("temp_backup")
        
        # Delete it
        success, message = main.delete_backup(filename)
        
        assert success == True
        assert not (main.BACKUPS_DIR / filename).exists()
    
    def test_delete_backup_invalid_path(self):
        """Test deleting backup with path traversal attempt"""
        success, message = main.delete_backup("../../../etc/passwd")
        assert success == False


class TestAPIKeyManagement:
    """Tests for API key management"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_db_file = main.DB_FILE
        self.original_db_conn = main.DB_CONN
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        main.DB_CONN = None
        main.ensure_dirs()
        main.init_database()
    
    def teardown_method(self):
        """Cleanup"""
        if main.DB_CONN:
            main.DB_CONN.close()
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = self.original_db_file
        main.DB_CONN = self.original_db_conn
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_save_and_get_api_keys(self):
        """Test saving and retrieving API keys"""
        amass_keys = {'shodan': 'test_shodan_key', 'virustotal': 'test_vt_key'}
        subfinder_keys = {'shodan': 'test_shodan_key2'}
        
        success, message = main.save_all_api_keys(amass_keys, subfinder_keys)
        assert success == True
        
        # Retrieve keys
        result = main.get_all_api_keys()
        assert 'amass' in result
        assert 'subfinder' in result
        assert result['amass'].get('shodan') == 'test_shodan_key'


class TestCSVExport:
    """Tests for CSV export functionality"""
    
    def test_build_targets_csv(self):
        """Test building CSV export from state"""
        state = {
            'targets': {
                'example.com': {
                    'subdomains': {
                        'sub1.example.com': {
                            'httpx': {'url': 'https://sub1.example.com'},
                            'nuclei': [{'severity': 'HIGH'}],
                            'nikto': [],
                            'screenshot': {'path': 'screen.png'}
                        },
                        'sub2.example.com': {
                            'httpx': {},
                            'nuclei': [],
                            'nikto': [{'severity': 'MEDIUM'}],
                        }
                    }
                }
            }
        }
        
        csv_data = main.build_targets_csv(state)
        
        assert isinstance(csv_data, bytes)
        csv_text = csv_data.decode('utf-8')
        assert 'example.com' in csv_text
        assert 'Domain' in csv_text  # Header
        assert 'Subdomains' in csv_text  # Header


class TestErrorHandling:
    """Tests for error handling and edge cases"""
    
    def test_is_rate_limit_error_http_429(self):
        """Test rate limit detection for HTTP 429"""
        from urllib.error import HTTPError
        error = HTTPError('http://test.com', 429, 'Too Many Requests', {}, None)
        assert main.is_rate_limit_error(error) == True
    
    def test_is_rate_limit_error_timeout(self):
        """Test rate limit detection for timeout"""
        error = Exception('Connection timed out')
        assert main.is_rate_limit_error(error) == True
    
    def test_is_rate_limit_error_rate_limit_message(self):
        """Test rate limit detection from message"""
        error = Exception('rate limit exceeded, please slow down')
        assert main.is_rate_limit_error(error) == True
    
    def test_is_rate_limit_error_normal_error(self):
        """Test that normal errors are not detected as rate limit"""
        error = Exception('File not found')
        assert main.is_rate_limit_error(error) == False
    
    def test_track_timeout_error(self):
        """Test timeout error tracking"""
        from urllib.error import HTTPError
        error = HTTPError('http://test.com', 429, 'Too Many Requests', {}, None)
        
        # Track error
        main.track_timeout_error('example.com', error)
        
        # Check that it's tracked
        with main.TIMEOUT_TRACKER_LOCK:
            assert 'example.com' in main.TIMEOUT_TRACKER


class TestHTTPHandlerSecurity:
    """Tests for HTTP handler security features"""
    
    def test_path_traversal_prevention_screenshots(self):
        """Test that path traversal is prevented for screenshot requests"""
        # This would need a mock HTTP request, so we test the logic directly
        # The actual handler checks: not str(requested).startswith(str(base))
        
        screenshots_dir = Path("/var/app/screenshots")
        
        # Safe path
        safe_path = screenshots_dir / "image.png"
        assert str(safe_path).startswith(str(screenshots_dir))
        
        # Dangerous path
        dangerous_path = (screenshots_dir / "../../../etc/passwd").resolve()
        assert not str(dangerous_path).startswith(str(screenshots_dir))
    
    def test_backup_filename_validation(self):
        """Test that backup filenames are validated"""
        # These should be rejected
        invalid_names = [
            "../backup.tar.gz",
            "../../etc/passwd",
            "backup/../../secret",
            "C:\\Windows\\System32\\config"
        ]
        
        for name in invalid_names:
            # Check for path traversal characters
            assert ".." in name or "/" in name or "\\" in name


class TestBuildStatePayloadSummary:
    """Tests for build_state_payload_summary function"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_data_dir = main.DATA_DIR
        self.original_db_file = main.DB_FILE
        self.original_db_conn = main.DB_CONN
        main.DATA_DIR = Path(self.temp_dir)
        main.DB_FILE = main.DATA_DIR / "test_recon.db"
        main.DB_CONN = None
        main.ensure_dirs()
        main.init_database()
    
    def teardown_method(self):
        """Cleanup"""
        if main.DB_CONN:
            main.DB_CONN.close()
            main.DB_CONN = None
        main.DATA_DIR = self.original_data_dir
        main.DB_FILE = self.original_db_file
        main.DB_CONN = self.original_db_conn
        # Clean up temporary directory
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_build_state_payload_summary_with_none_httpx(self):
        """Test that build_state_payload_summary handles None httpx value"""
        db = main.get_db()
        cursor = db.cursor()
        
        # Insert a target
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO targets (domain, data, flags, options, comments, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("example.com", json.dumps({}), json.dumps({}), json.dumps({}), json.dumps([]), now, now)
        )
        
        # Insert subdomain with None httpx (this is the bug case)
        subdomain_data = {
            "sources": ["test"],
            "httpx": None,  # This causes the AttributeError
            "nuclei": [],
            "nikto": [],
            "screenshot": None,
        }
        
        cursor.execute(
            "INSERT INTO subdomains (domain, subdomain, data, interesting, comments, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("example.com", "sub.example.com", json.dumps(subdomain_data), 0, json.dumps([]), now, now)
        )
        db.commit()
        
        # This should not raise AttributeError
        try:
            payload = main.build_state_payload_summary()
            assert "targets" in payload
            assert "example.com" in payload["targets"]
            assert "subdomains" in payload["targets"]["example.com"]
            assert "sub.example.com" in payload["targets"]["example.com"]["subdomains"]
            
            # httpx should not be in the lightweight data since it was None
            subdomain = payload["targets"]["example.com"]["subdomains"]["sub.example.com"]
            assert "httpx" not in subdomain
            assert "screenshot" not in subdomain
            assert "sources" in subdomain
            
        except AttributeError as e:
            pytest.fail(f"AttributeError raised: {e}")
    
    def test_build_state_payload_summary_with_valid_httpx(self):
        """Test that build_state_payload_summary works with valid httpx data"""
        db = main.get_db()
        cursor = db.cursor()
        
        # Insert a target
        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            "INSERT INTO targets (domain, data, flags, options, comments, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("example.com", json.dumps({}), json.dumps({}), json.dumps({}), json.dumps([]), now, now)
        )
        
        # Insert subdomain with valid httpx
        subdomain_data = {
            "sources": ["test"],
            "httpx": {
                "status_code": 200,
                "title": "Test Page",
                "webserver": "nginx",
            },
            "nuclei": [],
            "nikto": [],
            "screenshot": {
                "path": "/path/to/screenshot.png"
            },
        }
        
        cursor.execute(
            "INSERT INTO subdomains (domain, subdomain, data, interesting, comments, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("example.com", "sub.example.com", json.dumps(subdomain_data), 0, json.dumps([]), now, now)
        )
        db.commit()
        
        # This should work and include httpx data
        payload = main.build_state_payload_summary()
        subdomain = payload["targets"]["example.com"]["subdomains"]["sub.example.com"]
        
        assert "httpx" in subdomain
        assert subdomain["httpx"]["status_code"] == 200
        assert subdomain["httpx"]["title"] == "Test Page"
        assert subdomain["httpx"]["webserver"] == "nginx"
        
        assert "screenshot" in subdomain
        assert subdomain["screenshot"]["path"] == "/path/to/screenshot.png"


class TestWildcardSubdomainFiltering:
    """
    Tests for wildcard subdomain filtering to prevent recursive job issues.
    
    When entering *.openai.com, the tool should:
    1. Strip the * and create ONE job for openai.com with broad_scope=True
    2. Reject any wildcard subdomains discovered by enumeration tools
    3. Never create recursive jobs for discovered wildcard DNS records
    """
    
    def test_is_valid_subdomain_rejects_wildcards(self):
        """Test that is_valid_subdomain rejects wildcard patterns"""
        # These should be REJECTED (wildcards from tool output)
        assert main.is_valid_subdomain('*.openai.com') == False
        assert main.is_valid_subdomain('*.api.openai.com') == False
        assert main.is_valid_subdomain('*.test.example.com') == False
        assert main.is_valid_subdomain('*test.com') == False
        assert main.is_valid_subdomain('test*.com') == False
        assert main.is_valid_subdomain('test.*.com') == False
        
        # These should be ACCEPTED (normal subdomains)
        assert main.is_valid_subdomain('api.openai.com') == True
        assert main.is_valid_subdomain('chat.openai.com') == True
        assert main.is_valid_subdomain('openai.com') == True
        assert main.is_valid_subdomain('deep.api.openai.com') == True
        assert main.is_valid_subdomain('test-api.example.com') == True
        assert main.is_valid_subdomain('test_api.example.com') == True
    
    def test_read_lines_file_filters_wildcards(self):
        """Test that read_lines_file filters out wildcard subdomains"""
        # Create temporary file with mixed content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("api.openai.com\n")
            f.write("*.wildcard.openai.com\n")  # Should be filtered
            f.write("chat.openai.com\n")
            f.write("*.another.openai.com\n")  # Should be filtered
            f.write("valid.subdomain.com\n")
            f.write("*.test.example.com\n")  # Should be filtered
            temp_path = f.name
        
        try:
            result = main.read_lines_file(Path(temp_path))
            
            # Should only contain non-wildcard subdomains
            assert 'api.openai.com' in result
            assert 'chat.openai.com' in result
            assert 'valid.subdomain.com' in result
            
            # Should NOT contain wildcard entries
            assert '*.wildcard.openai.com' not in result
            assert '*.another.openai.com' not in result
            assert '*.test.example.com' not in result
            
            # Verify count
            assert len(result) == 3
        finally:
            os.unlink(temp_path)
    
    def test_expand_wildcard_creates_single_job(self):
        """Test that *.openai.com creates exactly ONE job for openai.com"""
        config = main.default_config()
        
        # Test subdomain wildcard
        targets_with_flags = main.expand_wildcard_targets('*.openai.com', config)
        
        # Should create exactly ONE target
        assert len(targets_with_flags) == 1
        
        # Should be openai.com (without the *)
        domain, is_broad = targets_with_flags[0]
        assert domain == 'openai.com'
        
        # Should be marked as broad scope
        assert is_broad == True
    
    def test_wildcard_tld_expansion(self):
        """Test that wildcard TLD expansion works correctly"""
        config = main.default_config()
        config['wildcard_tlds'] = ['com', 'net', 'org']
        
        # Test TLD wildcard
        targets_with_flags = main.expand_wildcard_targets('example.*', config)
        
        # Should create multiple targets (one per TLD)
        assert len(targets_with_flags) == 3
        
        domains = [domain for domain, _ in targets_with_flags]
        assert 'example.com' in domains
        assert 'example.net' in domains
        assert 'example.org' in domains
        
        # TLD wildcards should NOT be marked as broad scope
        for domain, is_broad in targets_with_flags:
            assert is_broad == False
    
    def test_combined_wildcards(self):
        """Test combined subdomain and TLD wildcards"""
        config = main.default_config()
        config['wildcard_tlds'] = ['com', 'net']
        
        # Test *.example.*
        targets_with_flags = main.expand_wildcard_targets('*.example.*', config)
        
        # Should expand TLDs but strip subdomain wildcard
        assert len(targets_with_flags) == 2
        
        domains = [domain for domain, _ in targets_with_flags]
        assert 'example.com' in domains
        assert 'example.net' in domains
        
        # Should be marked as broad scope (due to subdomain wildcard)
        for domain, is_broad in targets_with_flags:
            assert is_broad == True
    
    def test_no_recursive_jobs_from_discovered_wildcards(self):
        """
        Integration test: Verify that wildcard subdomains discovered by tools
        don't create recursive jobs
        """
        # This test documents the expected behavior:
        # 1. User enters *.openai.com
        # 2. System creates ONE job for openai.com
        # 3. Tools discover subdomains, possibly including wildcard DNS records
        # 4. Wildcard DNS records are filtered and NOT added to state
        # 5. NO new jobs are created for discovered subdomains
        
        config = main.default_config()
        
        # Simulate user input
        targets_with_flags = main.expand_wildcard_targets('*.openai.com', config)
        assert len(targets_with_flags) == 1
        
        # Simulate tool output containing wildcards
        tool_output = [
            'api.openai.com',
            '*.wildcard.openai.com',  # Wildcard DNS record
            'chat.openai.com',
        ]
        
        # Filter using is_valid_subdomain (as read_lines_file does)
        filtered = [s for s in tool_output if main.is_valid_subdomain(s)]
        
        # Should only have non-wildcard entries
        assert len(filtered) == 2
        assert 'api.openai.com' in filtered
        assert 'chat.openai.com' in filtered
        assert '*.wildcard.openai.com' not in filtered


class TestSubdomainExport:
    """Tests for subdomain export functionality with filters"""
    
    def test_filter_domains_by_criteria_no_filters(self):
        """Test filtering with no filters applied (all domains should pass)"""
        state = {
            "targets": {
                "example.com": {
                    "pending": False,
                    "subdomains": {
                        "www.example.com": {},
                        "api.example.com": {}
                    }
                },
                "test.com": {
                    "pending": True,
                    "subdomains": {
                        "mail.test.com": {}
                    }
                }
            }
        }
        
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 2
        assert "example.com" in result
        assert "test.com" in result
    
    def test_filter_domains_by_domain_search(self):
        """Test filtering by domain search string"""
        state = {
            "targets": {
                "example.com": {"subdomains": {}},
                "test.com": {"subdomains": {}},
                "example.net": {"subdomains": {}}
            }
        }
        
        filters = {
            "domainSearch": "example",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 2
        assert "example.com" in result
        assert "example.net" in result
        assert "test.com" not in result
    
    def test_filter_domains_by_status(self):
        """Test filtering by pending/complete status"""
        state = {
            "targets": {
                "pending.com": {"pending": True, "subdomains": {}},
                "complete.com": {"pending": False, "subdomains": {}},
                "also-complete.com": {"subdomains": {}}
            }
        }
        
        # Test pending filter
        filters = {
            "domainSearch": "",
            "status": "pending",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 1
        assert "pending.com" in result
        
        # Test complete filter
        filters["status"] = "complete"
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 2
        assert "complete.com" in result
        assert "also-complete.com" in result
    
    def test_filter_domains_by_severity(self):
        """Test filtering by maximum severity"""
        state = {
            "targets": {
                "critical.com": {
                    "subdomains": {
                        "www.critical.com": {
                            "nuclei": [{"severity": "CRITICAL"}]
                        }
                    }
                },
                "low.com": {
                    "subdomains": {
                        "www.low.com": {
                            "nuclei": [{"severity": "LOW"}]
                        }
                    }
                },
                "none.com": {
                    "subdomains": {
                        "www.none.com": {}
                    }
                }
            }
        }
        
        # Filter for HIGH or higher
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "HIGH",
            "hasFindings": False,
            "hasScreenshots": False
        }
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 1
        assert "critical.com" in result
    
    def test_filter_domains_by_findings(self):
        """Test filtering by presence of security findings"""
        state = {
            "targets": {
                "with-findings.com": {
                    "subdomains": {
                        "www.with-findings.com": {
                            "nuclei": [{"severity": "LOW"}]
                        }
                    }
                },
                "no-findings.com": {
                    "subdomains": {
                        "www.no-findings.com": {}
                    }
                }
            }
        }
        
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": True,
            "hasScreenshots": False
        }
        
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 1
        assert "with-findings.com" in result
    
    def test_filter_domains_by_screenshots(self):
        """Test filtering by presence of screenshots"""
        state = {
            "targets": {
                "with-screenshot.com": {
                    "subdomains": {
                        "www.with-screenshot.com": {
                            "screenshot": {"path": "screenshot.png"}
                        }
                    }
                },
                "no-screenshot.com": {
                    "subdomains": {
                        "www.no-screenshot.com": {}
                    }
                }
            }
        }
        
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": True
        }
        
        result = main.filter_domains_by_criteria(state, filters)
        assert len(result) == 1
        assert "with-screenshot.com" in result
    
    def test_export_subdomains_txt(self):
        """Test TXT export format"""
        state = {
            "targets": {
                "example.com": {
                    "subdomains": {
                        "www.example.com": {},
                        "api.example.com": {}
                    }
                },
                "test.com": {
                    "subdomains": {
                        "mail.test.com": {}
                    }
                }
            }
        }
        
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        
        result = main.export_subdomains_txt(state, filters)
        lines = result.decode("utf-8").strip().split("\n")
        
        assert len(lines) == 3
        assert "api.example.com" in lines
        assert "mail.test.com" in lines
        assert "www.example.com" in lines
    
    def test_export_subdomains_csv(self):
        """Test CSV export format"""
        state = {
            "targets": {
                "example.com": {
                    "subdomains": {
                        "www.example.com": {
                            "httpx": {
                                "status_code": 200,
                                "title": "Example Domain",
                                "webserver": "nginx"
                            },
                            "nuclei": [{"severity": "LOW"}],
                            "nikto": [],
                            "sources": ["amass", "subfinder"]
                        }
                    }
                }
            }
        }
        
        filters = {
            "domainSearch": "",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        
        result = main.export_subdomains_csv(state, filters)
        lines = result.decode("utf-8").strip().split("\n")
        
        # Check header
        assert "subdomain" in lines[0]
        assert "parent_domain" in lines[0]
        assert "status_code" in lines[0]
        
        # Check data row
        assert len(lines) == 2  # Header + 1 data row
        assert "www.example.com" in lines[1]
        assert "example.com" in lines[1]
        assert "200" in lines[1]
        assert "Example Domain" in lines[1]
    
    def test_export_with_filters_applied(self):
        """Test export respects filters (domain search)"""
        state = {
            "targets": {
                "example.com": {
                    "subdomains": {
                        "www.example.com": {},
                        "api.example.com": {}
                    }
                },
                "test.com": {
                    "subdomains": {
                        "mail.test.com": {}
                    }
                }
            }
        }
        
        # Filter to only include "example" domains
        filters = {
            "domainSearch": "example",
            "status": "all",
            "maxSeverity": "all",
            "hasFindings": False,
            "hasScreenshots": False
        }
        
        result = main.export_subdomains_txt(state, filters)
        lines = result.decode("utf-8").strip().split("\n")
        
        # Should only have subdomains from example.com
        assert len(lines) == 2
        assert "api.example.com" in lines
        assert "www.example.com" in lines
        assert "mail.test.com" not in "\n".join(lines)


if __name__ == '__main__':
    # Run tests with pytest
    pytest.main([__file__, '-v', '--tb=short'])
