import ast
import sys
import os

files_to_check = [
    r'C:\playrepo\pentest\dashboard\app.py',
    r'C:\playrepo\pentest\dashboard\scanner_runner.py',
    r'C:\playrepo\pentest\dashboard\scheduler.py',
    r'C:\playrepo\pentest\pentester\scanners\ssti_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\xxe_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\ldap_scanner.py',
    r'C:\playrepo\pentest\pentester\scanners\secrets_scanner.py',
]

passed = 0
failed = 0
failed_files = []

for filepath in files_to_check:
    filename = os.path.basename(filepath)
    try:
        with open(filepath, 'r') as f:
            code = f.read()
        ast.parse(code)
        print(f"✓ {filename} - PASS")
        passed += 1
    except SyntaxError as e:
        print(f"✗ {filename} - SYNTAX ERROR")
        print(f"  Line {e.lineno}: {e.msg}")
        if e.text:
            print(f"  {e.text.strip()}")
        failed += 1
        failed_files.append(filename)
    except FileNotFoundError as e:
        print(f"✗ {filename} - FILE NOT FOUND")
        failed += 1
        failed_files.append(filename)
    except Exception as e:
        print(f"✗ {filename} - ERROR: {e}")
        failed += 1
        failed_files.append(filename)

print(f"\n{'='*50}")
print(f"SUMMARY: {passed} passed, {failed} failed")
print(f"{'='*50}")

if failed_files:
    print(f"\nFailed files:")
    for f in failed_files:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("\n✓ All files passed syntax checks!")
