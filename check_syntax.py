#!/usr/bin/env python3
"""Quick syntax checker for Python files"""
import ast
import sys

files_to_check = [
    r'C:\playrepo\pentest\dashboard\app.py',
    r'C:\playrepo\pentest\dashboard\scanner_runner.py',
    r'C:\playrepo\pentest\dashboard\scheduler.py',
    r'C:\playrepo\pentest\pentester\scanners\ssti_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\xxe_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\ldap_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\secrets_scanner.py',
]

passed = []
failed = []

for filepath in files_to_check:
    filename = filepath.split('\\')[-1]
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        ast.parse(code)
        passed.append(filename)
        print(f"✓ {filename}")
    except SyntaxError as e:
        failed.append((filename, f"Line {e.lineno}: {e.msg}"))
        print(f"✗ {filename} - SYNTAX ERROR at line {e.lineno}: {e.msg}")
    except FileNotFoundError:
        failed.append((filename, "File not found"))
        print(f"✗ {filename} - FILE NOT FOUND")
    except Exception as e:
        failed.append((filename, str(e)))
        print(f"✗ {filename} - ERROR: {e}")

print(f"\n{'='*60}")
print(f"PASSED: {len(passed)}/{len(files_to_check)}")
print(f"FAILED: {len(failed)}/{len(files_to_check)}")
print(f"{'='*60}")

if failed:
    print("\nFailed files:")
    for fname, error in failed:
        print(f"  - {fname}: {error}")
    sys.exit(1)
else:
    print("\n✓ All files passed syntax checks!")
    sys.exit(0)
