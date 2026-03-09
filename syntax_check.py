import ast
import sys

files_to_check = [
    r'C:\playrepo\pentest\pentester\config.py',
    r'C:\playrepo\pentest\pentester\report_generator.py',
    r'C:\playrepo\pentest\pentester\ai_analyzer.py',
    r'C:\playrepo\pentest\pentester\main.py',
    r'C:\playrepo\pentest\dashboard\app.py',
    r'C:\playrepo\pentest\dashboard\scanner_runner.py',
]

for filepath in files_to_check:
    try:
        with open(filepath, 'r') as f:
            code = f.read()
        ast.parse(code)
        print(f"✓ {filepath.split(chr(92))[-1]} OK")
    except SyntaxError as e:
        print(f"✗ {filepath.split(chr(92))[-1]} SYNTAX ERROR: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"✗ {filepath.split(chr(92))[-1]} NOT FOUND: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ {filepath.split(chr(92))[-1]} ERROR: {e}")
        sys.exit(1)

print("\nAll files passed syntax checks!")
