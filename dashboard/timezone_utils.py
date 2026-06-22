"""
Timezone utilities for consistent time display across AutoPenTest dashboard.
Converts UTC times to user's local timezone.
"""

from datetime import datetime
import pytz
import os

# Default timezone - can be overridden by user
DEFAULT_TIMEZONE = os.environ.get("DEFAULT_TIMEZONE", "UTC")

def get_user_timezone(session_data=None, browser_tz=None):
    """
    Get user's timezone from session or browser detection.
    Fallback order: session -> browser -> environment -> UTC
    """
    if session_data and session_data.get('timezone'):
        try:
            pytz.timezone(session_data['timezone'])
            return session_data['timezone']
        except pytz.exceptions.UnknownTimeZoneError:
            pass
    
    if browser_tz:
        try:
            pytz.timezone(browser_tz)
            return browser_tz
        except pytz.exceptions.UnknownTimeZoneError:
            pass
    
    try:
        pytz.timezone(DEFAULT_TIMEZONE)
        return DEFAULT_TIMEZONE
    except pytz.exceptions.UnknownTimeZoneError:
        return "UTC"


def utc_to_local(utc_datetime_str, user_timezone=None):
    """
    Convert ISO format UTC datetime string to user's local time.
    
    Args:
        utc_datetime_str: ISO format string (e.g., "2026-06-22T12:10:49.790+08:00" or "2026-06-22T12:10:49")
        user_timezone: Timezone name (e.g., "Asia/Singapore", "US/Eastern")
    
    Returns:
        Localized datetime object or None if parsing fails
    """
    if not utc_datetime_str:
        return None
    
    if user_timezone is None:
        user_timezone = DEFAULT_TIMEZONE
    
    try:
        # Parse the UTC datetime
        if isinstance(utc_datetime_str, str):
            # Try parsing ISO format with microseconds
            try:
                dt = datetime.fromisoformat(utc_datetime_str.replace('Z', '+00:00'))
            except ValueError:
                # Try without microseconds
                dt = datetime.fromisoformat(utc_datetime_str[:19])
        else:
            dt = utc_datetime_str
        
        # If datetime is naive, assume it's UTC
        if dt.tzinfo is None:
            dt = pytz.UTC.localize(dt)
        
        # Convert to user's timezone
        user_tz = pytz.timezone(user_timezone)
        local_dt = dt.astimezone(user_tz)
        
        return local_dt
    except Exception as e:
        print(f"[TZ_ERROR] Failed to convert {utc_datetime_str}: {e}")
        return None


def format_scan_time(utc_datetime_str, user_timezone=None, format_style='full'):
    """
    Format UTC time for display in scan context.
    
    Args:
        utc_datetime_str: ISO format UTC datetime string
        user_timezone: User's timezone
        format_style: 'full' (e.g., "2026-06-22 12:10:49 SGT"), 
                     'short' (e.g., "12:10:49"), 
                     'date' (e.g., "2026-06-22")
    
    Returns:
        Formatted time string or empty string if parsing fails
    """
    local_dt = utc_to_local(utc_datetime_str, user_timezone)
    
    if local_dt is None:
        return "N/A"
    
    if format_style == 'short':
        return local_dt.strftime("%H:%M:%S")
    elif format_style == 'date':
        return local_dt.strftime("%Y-%m-%d")
    elif format_style == 'time-only':
        return local_dt.strftime("%H:%M")
    else:  # full
        tz_abbr = local_dt.strftime("%Z")
        return local_dt.strftime(f"%Y-%m-%d %H:%M:%S {tz_abbr}")


def format_scan_duration(started_at_str, completed_at_str, user_timezone=None):
    """
    Format scan duration (e.g., "5m 23s" or "1h 2m").
    
    Args:
        started_at_str: ISO format UTC start datetime
        completed_at_str: ISO format UTC end datetime (or None if running)
        user_timezone: User's timezone
    
    Returns:
        Formatted duration string
    """
    if not started_at_str:
        return "N/A"
    
    start_dt = utc_to_local(started_at_str, user_timezone)
    
    if start_dt is None:
        return "N/A"
    
    if completed_at_str:
        end_dt = utc_to_local(completed_at_str, user_timezone)
        if end_dt:
            duration = end_dt - start_dt
        else:
            return "N/A"
    else:
        # Still running - calculate from start to now
        duration = datetime.now(pytz.timezone(user_timezone or DEFAULT_TIMEZONE)) - start_dt
    
    total_seconds = int(duration.total_seconds())
    
    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        if seconds:
            return f"{minutes}m {seconds}s"
        else:
            return f"{minutes}m"
    else:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        if minutes:
            return f"{hours}h {minutes}m"
        else:
            return f"{hours}h"


def get_timezone_offset(user_timezone=None):
    """
    Get timezone offset from UTC (e.g., "+08:00" or "-05:00").
    
    Args:
        user_timezone: Timezone name
    
    Returns:
        Offset string or empty string
    """
    if user_timezone is None:
        user_timezone = DEFAULT_TIMEZONE
    
    try:
        tz = pytz.timezone(user_timezone)
        now = datetime.now(tz)
        offset = now.strftime("%z")
        # Format as +HH:MM
        if offset:
            return f"{offset[:3]}:{offset[3:]}"
        return ""
    except Exception:
        return ""


# List of common timezones
COMMON_TIMEZONES = [
    'UTC',
    'Asia/Singapore',
    'Asia/Hong_Kong',
    'Asia/Tokyo',
    'Asia/Shanghai',
    'Asia/Kolkata',
    'Europe/London',
    'Europe/Paris',
    'Europe/Berlin',
    'US/Eastern',
    'US/Central',
    'US/Mountain',
    'US/Pacific',
    'Australia/Sydney',
    'Australia/Melbourne',
]
