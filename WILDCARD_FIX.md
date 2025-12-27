# Wildcard Subdomain Filtering Fix

## Issue

When entering wildcard domains like `*.openai.com`, the tool was accepting wildcard DNS records discovered by enumeration tools (e.g., `*.cdn.openai.com`, `*.static.openai.com`). While this didn't directly cause recursive job creation, it was incorrect behavior that could lead to confusion and potential issues.

## Root Cause

The `is_valid_subdomain()` function in `main.py` was explicitly allowing wildcards in its validation regex pattern:

```python
# OLD CODE (incorrect)
domain_pattern = r'^(\*\.)?[a-z0-9]...'  # Accepts *.domain.com
```

This function is used to validate tool output (discovered subdomains), where wildcards should NEVER appear. Wildcard handling should only occur in user input via `expand_wildcard_targets()`.

## Solution

Modified `is_valid_subdomain()` to explicitly reject any string containing the `*` character:

```python
# NEW CODE (correct)
def is_valid_subdomain(text: str) -> bool:
    """
    Validate that a string looks like a valid domain or subdomain.
    Returns False for ANSI codes, error messages, status messages, wildcards, etc.
    
    NOTE: This function is used to validate tool output (discovered subdomains).
    Wildcards are rejected here because tools should return concrete subdomains,
    not wildcard patterns. Wildcard inputs are handled separately by expand_wildcard_targets().
    """
    # ... (validation code)
    
    # Reject wildcards - these should not appear in tool output
    if '*' in cleaned:
        return False
    
    # ... (rest of validation)
```

## Expected Behavior

### 1. User Input Processing
When a user enters `*.openai.com`:
- `expand_wildcard_targets()` strips the `*.` prefix
- Creates **exactly ONE** job for `openai.com` with `broad_scope=True`
- No recursive jobs are created

### 2. Tool Discovery
When enumeration tools discover subdomains:
- Normal subdomains like `api.openai.com` are accepted
- Wildcard DNS records like `*.cdn.openai.com` are **filtered out**
- Only valid concrete subdomains are added to the state
- No new jobs are created from discovered subdomains

### 3. Complete Flow Example

```
User Input: *.openai.com

1. expand_wildcard_targets('*.openai.com')
   → [('openai.com', True)]
   → Creates 1 job for openai.com

2. Enumeration tools discover:
   - api.openai.com          ✓ Valid
   - chat.openai.com         ✓ Valid
   - *.cdn.openai.com        ✗ Filtered (wildcard)
   - auth.openai.com         ✓ Valid
   - *.static.openai.com     ✗ Filtered (wildcard)

3. State updated with valid subdomains only
   - api.openai.com
   - chat.openai.com
   - auth.openai.com

4. No new jobs created
   → Still only 1 job for openai.com
```

## Testing

Added comprehensive test suite in `test_main.py`:
- `TestWildcardSubdomainFiltering` class with 7 test cases
- Tests cover wildcard rejection, filtering, expansion, and integration
- All tests pass successfully

### Key Test Cases

1. **Wildcard Rejection**: Verify `is_valid_subdomain()` rejects wildcards
2. **File Filtering**: Verify `read_lines_file()` filters wildcard entries
3. **Single Job Creation**: Verify `*.domain.com` creates exactly 1 job
4. **TLD Expansion**: Verify `domain.*` expands to multiple TLDs correctly
5. **Integration**: End-to-end test of the complete flow

## Files Changed

- `main.py`: Modified `is_valid_subdomain()` function
- `test_main.py`: Added `TestWildcardSubdomainFiltering` test class
- `WILDCARD_FIX.md`: This documentation file

## Verification

Run the tests:
```bash
python3 test_main.py
```

Or test manually:
```bash
python3 main.py '*.openai.com' --skip-nikto
```

The tool will:
- Create exactly 1 job for `openai.com`
- Filter out any wildcard DNS records discovered
- Never create recursive jobs

## Impact

- **Fixes**: Prevents wildcard DNS records from being stored in state
- **Maintains**: All existing wildcard expansion functionality for user input
- **Improves**: Code clarity by separating concerns (user input vs tool output)
- **No Breaking Changes**: All existing tests pass

## Future Considerations

This fix ensures that:
1. User wildcard input (`*.domain.com`) is handled correctly by `expand_wildcard_targets()`
2. Tool output is validated properly by `is_valid_subdomain()`
3. The two concerns remain separated and well-defined
4. The codebase is protected against any future issues with wildcard handling
