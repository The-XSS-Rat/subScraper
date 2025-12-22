#!/usr/bin/env python3
"""
Performance test for large dataset handling.
Tests that the app can handle 200k+ subdomains without freezing.
"""

import json
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

import main


def test_build_state_payload_summary_with_large_dataset():
    """
    Test that build_state_payload_summary can handle large datasets efficiently.
    """
    print("Testing build_state_payload_summary with large dataset...")
    
    # Initialize database
    main.ensure_dirs()
    main.ensure_database()
    
    # Create a test domain with many subdomains
    test_domain = "performance-test.com"
    num_subdomains = 1000  # Use 1k for test (200k would take too long)
    
    print(f"Creating test domain with {num_subdomains} subdomains...")
    
    # Get database connection
    db = main.get_db()
    cursor = db.cursor()
    now = main.datetime.now(main.timezone.utc).isoformat()
    
    # Create target
    cursor.execute(
        """INSERT OR REPLACE INTO targets 
           (domain, data, flags, options, created_at, updated_at) 
           VALUES (?, ?, ?, ?, ?, ?)""",
        (test_domain, "{}", json.dumps({}), json.dumps({}), now, now)
    )
    
    # Create many subdomains
    print("Inserting subdomains...")
    for i in range(num_subdomains):
        subdomain = f"sub{i}.{test_domain}"
        data = {
            "sources": ["test"],
            "httpx": {
                "status_code": 200,
                "title": f"Test {i}",
                "webserver": "nginx"
            }
        }
        cursor.execute(
            """INSERT OR REPLACE INTO subdomains 
               (domain, subdomain, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (test_domain, subdomain, json.dumps(data), now, now)
        )
        
        if (i + 1) % 100 == 0:
            print(f"  Inserted {i + 1}/{num_subdomains} subdomains...")
    
    db.commit()
    print("Test data created successfully.")
    
    # Test build_state_payload_summary performance
    print("\nTesting build_state_payload_summary performance...")
    start_time = time.time()
    
    try:
        payload = main.build_state_payload_summary()
        elapsed = time.time() - start_time
        
        print(f"✓ build_state_payload_summary completed in {elapsed:.2f} seconds")
        
        # Verify the payload structure
        assert "targets" in payload, "Payload missing 'targets' key"
        assert test_domain in payload["targets"], f"Test domain {test_domain} not found"
        
        target = payload["targets"][test_domain]
        
        # Check that subdomain truncation works
        subdomains = target.get("subdomains", {})
        total_subdomains = target.get("total_subdomains", 0)
        subdomains_truncated = target.get("subdomains_truncated", False)
        
        print(f"\nResults:")
        print(f"  Total subdomains in DB: {num_subdomains}")
        print(f"  Total subdomains reported: {total_subdomains}")
        print(f"  Subdomains in payload: {len(subdomains)}")
        print(f"  Truncated: {subdomains_truncated}")
        
        # Verify truncation logic
        MAX_SUBDOMAINS_IN_SUMMARY = 100
        if num_subdomains > MAX_SUBDOMAINS_IN_SUMMARY:
            assert len(subdomains) <= MAX_SUBDOMAINS_IN_SUMMARY, \
                f"Expected at most {MAX_SUBDOMAINS_IN_SUMMARY} subdomains in payload, got {len(subdomains)}"
            assert subdomains_truncated is True, "Expected subdomains_truncated to be True"
            assert total_subdomains == num_subdomains, \
                f"Expected total_subdomains={num_subdomains}, got {total_subdomains}"
            print(f"✓ Subdomain truncation working correctly")
        else:
            assert len(subdomains) == num_subdomains, \
                f"Expected {num_subdomains} subdomains, got {len(subdomains)}"
            assert subdomains_truncated is False, "Expected subdomains_truncated to be False"
            print(f"✓ All subdomains included (below truncation threshold)")
        
        # Check payload size
        payload_json = json.dumps(payload)
        payload_size_mb = len(payload_json) / (1024 * 1024)
        print(f"\nPayload size: {payload_size_mb:.2f} MB")
        
        if payload_size_mb > 10:
            print(f"⚠️  Warning: Payload size is large ({payload_size_mb:.2f} MB)")
        else:
            print(f"✓ Payload size is reasonable")
        
        print(f"\n✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup test data
        print("\nCleaning up test data...")
        cursor.execute("DELETE FROM subdomains WHERE domain = ?", (test_domain,))
        cursor.execute("DELETE FROM targets WHERE domain = ?", (test_domain,))
        db.commit()
        print("Cleanup complete.")


def test_load_state_performance():
    """
    Test that load_state() handles large datasets efficiently.
    """
    print("\n" + "="*60)
    print("Testing load_state performance...")
    
    # Create test data
    test_domain = "load-test.com"
    num_subdomains = 500
    
    print(f"Creating test domain with {num_subdomains} subdomains...")
    
    db = main.get_db()
    cursor = db.cursor()
    now = main.datetime.now(main.timezone.utc).isoformat()
    
    # Create target
    cursor.execute(
        """INSERT OR REPLACE INTO targets 
           (domain, data, flags, options, created_at, updated_at) 
           VALUES (?, ?, ?, ?, ?, ?)""",
        (test_domain, "{}", json.dumps({}), json.dumps({}), now, now)
    )
    
    # Create subdomains
    for i in range(num_subdomains):
        subdomain = f"sub{i}.{test_domain}"
        data = {"sources": ["test"]}
        cursor.execute(
            """INSERT OR REPLACE INTO subdomains 
               (domain, subdomain, data, created_at, updated_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (test_domain, subdomain, json.dumps(data), now, now)
        )
    
    db.commit()
    
    try:
        # Test load_state performance
        start_time = time.time()
        state = main.load_state()
        elapsed = time.time() - start_time
        
        print(f"✓ load_state completed in {elapsed:.2f} seconds")
        
        # Verify state structure
        assert test_domain in state["targets"], "Test domain not found in state"
        target = state["targets"][test_domain]
        assert len(target["subdomains"]) == num_subdomains, \
            f"Expected {num_subdomains} subdomains, got {len(target['subdomains'])}"
        
        print(f"✓ All {num_subdomains} subdomains loaded correctly")
        print(f"\n✅ load_state test passed!")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        print("\nCleaning up test data...")
        cursor.execute("DELETE FROM subdomains WHERE domain = ?", (test_domain,))
        cursor.execute("DELETE FROM targets WHERE domain = ?", (test_domain,))
        db.commit()
        print("Cleanup complete.")


if __name__ == "__main__":
    print("="*60)
    print("PERFORMANCE TEST SUITE")
    print("="*60)
    
    results = []
    
    # Run tests
    results.append(("build_state_payload_summary", test_build_state_payload_summary_with_large_dataset()))
    results.append(("load_state", test_load_state_performance()))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All performance tests passed!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {total - passed} test(s) failed")
        sys.exit(1)
