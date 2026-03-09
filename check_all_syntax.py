#!/usr/bin/env python3
"""Syntax checker for all Python files in pentester directory"""
import ast
import os

base_dir = r'C:\playrepo\pentest\pentester'
errors = []
checked = 0

for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            checked += 1
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    code = f.read()
                ast.parse(code)
                rel_path = os.path.relpath(filepath, base_dir)
                print(f"✓ {rel_path}")
            except SyntaxError as e:
                rel_path = os.path.relpath(filepath, base_dir)
                errors.append(f"{rel_path}: Line {e.lineno}: {e.msg}")
                print(f"✗ {rel_path} - SYNTAX ERROR at line {e.lineno}: {e.msg}")
            except Exception as e:
                rel_path = os.path.relpath(filepath, base_dir)
                errors.append(f"{rel_path}: {str(e)}")
                print(f"✗ {rel_path} - ERROR: {e}")

print(f"\n{'='*60}")
print(f"Checked: {checked} files")
print(f"Errors: {len(errors)}")
print(f"{'='*60}")

if errors:
    print("\nSyntax errors found:")
    for error in errors:
        print(f"  {error}")
else:
    print("\nAll OK")
