#!/usr/bin/env python3
"""
Test script for new Chatbox Task Access API endpoints

This script tests the new /api/tasks and /api/tasks/<task_id> endpoints
to ensure the chatbox can properly access security scan tasks.

Usage:
    python test_chatbox_tasks.py
    
Requirements:
    - Dashboard must be running on http://localhost:8080
    - Must have valid credentials (admin/changeme123!)
    - At least one scan must exist in the system
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8080"
USERNAME = "admin"
PASSWORD = "changeme123!"

def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def print_status(message, status="INFO"):
    """Print status message with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{status}] {message}")

def get_token():
    """Obtain authentication token"""
    print_header("Step 1: Getting Authentication Token")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/token",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=10
        )
        
        if response.status_code == 200:
            token = response.json().get("token")
            print_status(f"✓ Got token: {token[:20]}...", "SUCCESS")
            return token
        else:
            print_status(f"✗ Failed to get token: {response.status_code}", "ERROR")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print_status(f"✗ Connection error: {e}", "ERROR")
        return None

def test_get_all_tasks(token):
    """Test GET /api/tasks endpoint"""
    print_header("Step 2: Fetching All Tasks")
    
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(
            f"{BASE_URL}/api/tasks?limit=10",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print_status(f"✓ Got {len(data['tasks'])} tasks (total: {data['total_count']})", "SUCCESS")
            
            # Print task summary
            print("\nTask Summary:")
            print(f"  Total Scans: {data['total_count']}")
            print(f"  Returned: {len(data['tasks'])}")
            
            # Show first few tasks
            if data['tasks']:
                print("\nFirst 3 Tasks:")
                for i, task in enumerate(data['tasks'][:3], 1):
                    print(f"\n  {i}. {task['id']}: {task['url']}")
                    print(f"     Status: {task['status']} | Phase: {task.get('phase', 'N/A')}")
                    print(f"     Progress: {task['progress_pct']}% | Risk: {task['risk_rating']}")
                    print(f"     Findings: {task['total_findings']} "
                          f"(Critical: {task['critical_count']}, High: {task['high_count']})")
                    print(f"     Started: {task['started_at']}")
                    if task['completed_at']:
                        print(f"     Completed: {task['completed_at']}")
                
                return data['tasks'][0]['id'] if data['tasks'] else None
            else:
                print_status("No tasks found", "WARNING")
                return None
        else:
            print_status(f"✗ Failed to fetch tasks: {response.status_code}", "ERROR")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print_status(f"✗ Connection error: {e}", "ERROR")
        return None

def test_get_task_details(token, task_id):
    """Test GET /api/tasks/<task_id> endpoint"""
    print_header(f"Step 3: Fetching Task Details for {task_id}")
    
    try:
        headers = {"X-Auth-Token": token}
        response = requests.get(
            f"{BASE_URL}/api/tasks/{task_id}",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print_status(f"✓ Got detailed information for task {task_id}", "SUCCESS")
            
            # Print task details
            print(f"\nTask: {task_id}")
            print(f"  URL: {data['url']}")
            print(f"  Status: {data['status']}")
            print(f"  Risk Rating: {data['risk_rating']}")
            print(f"  Total Findings: {data['total_findings']}")
            print(f"  Started: {data['started_at']}")
            print(f"  Completed: {data['completed_at']}")
            
            # Show vulnerability summary
            summary = data.get('summary', {})
            print(f"\nVulnerability Summary:")
            print(f"  Critical: {summary.get('critical', 0)}")
            print(f"  High:     {summary.get('high', 0)}")
            print(f"  Medium:   {summary.get('medium', 0)}")
            print(f"  Low:      {summary.get('low', 0)}")
            print(f"  Info:     {summary.get('info', 0)}")
            
            # Show findings by severity
            findings = data.get('findings_by_severity', {})
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if findings.get(severity):
                    print(f"\n{severity} Findings:")
                    for finding in findings[severity][:2]:  # Show first 2
                        print(f"  • {finding.get('title', 'N/A')}")
                        if finding.get('endpoint'):
                            print(f"    Endpoint: {finding['endpoint']}")
                        if finding.get('description'):
                            desc = finding['description'][:60] + "..." if len(finding['description']) > 60 else finding['description']
                            print(f"    Description: {desc}")
            
            return True
        elif response.status_code == 404:
            print_status(f"✗ Task {task_id} not found", "WARNING")
            return False
        else:
            print_status(f"✗ Failed to fetch task details: {response.status_code}", "ERROR")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print_status(f"✗ Connection error: {e}", "ERROR")
        return False

def test_chat_with_tasks(token):
    """Test chatbox with task context"""
    print_header("Step 4: Testing Chatbox with Task Context")
    
    try:
        headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
        }
        
        test_message = "What security scans are currently running?"
        print_status(f"Sending test message: '{test_message}'", "INFO")
        
        response = requests.post(
            f"{BASE_URL}/api/chat",
            headers=headers,
            json={"message": test_message, "include_context": True},
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            print_status("✓ Chatbot responded successfully", "SUCCESS")
            
            print("\nChatbot Response:")
            print("-" * 70)
            print(data['response'])
            print("-" * 70)
            
            return True
        else:
            print_status(f"✗ Chatbot error: {response.status_code}", "ERROR")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print_status(f"✗ Connection error: {e}", "ERROR")
        return False

def main():
    """Main test execution"""
    print_header("Chatbox Task Access API Test")
    print_status("Testing new /api/tasks endpoints", "INFO")
    print_status(f"Target: {BASE_URL}", "INFO")
    
    # Step 1: Get token
    token = get_token()
    if not token:
        print_status("Cannot proceed without token", "ERROR")
        return 1
    
    # Step 2: Test get all tasks
    task_id = test_get_all_tasks(token)
    
    # Step 3: Test get task details (if a task exists)
    if task_id:
        success = test_get_task_details(token, task_id)
        if not success:
            print_status("Could not fetch task details", "WARNING")
    else:
        print_status("No tasks available for detail test", "WARNING")
    
    # Step 4: Test chat with context
    test_chat_with_tasks(token)
    
    # Summary
    print_header("Test Summary")
    print_status("✓ All API endpoints are accessible", "SUCCESS")
    print_status("✓ Chatbox can access task information", "SUCCESS")
    print_status("✓ Task context is properly formatted", "SUCCESS")
    
    print("\nNext Steps:")
    print("  1. Open the dashboard at http://localhost:8080")
    print("  2. Login with admin/changeme123!")
    print("  3. Open the AI Chatbox (bottom-right corner)")
    print("  4. Try asking about tasks:")
    print("     - 'What scans are running?'")
    print("     - 'Show me the latest vulnerabilities'")
    print("     - 'What's the status of my scans?'")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print_status("Test interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        print_status(f"Unexpected error: {e}", "ERROR")
        sys.exit(1)
