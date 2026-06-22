import sys
sys.path.insert(0, '/app/pentest_lib' if '/app' in sys.argv[0] else './pentester')
from scanners.idor_scanner import IDORScanner

scanner = IDORScanner(target_url='http://172.18.0.4')
try:
    findings = scanner.run()
    print(f'Found {len(findings)} IDOR issues')
    for f in findings:
        print(f)
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
