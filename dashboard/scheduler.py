"""APScheduler-based scan scheduler for AutoPenTest dashboard."""
import os, json, threading
from datetime import datetime

_schedules: dict = {}  # schedule_id -> schedule_config
_schedules_lock = threading.Lock()

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    _scheduler = BackgroundScheduler(daemon=True)
    _SCHEDULER_AVAILABLE = True
except ImportError:
    _scheduler = None
    _SCHEDULER_AVAILABLE = False


def _run_scheduled_scan(schedule_id: str, url: str, report_dir: str):
    """Execute a scheduled scan."""
    try:
        import uuid
        from scanner_runner import run_scan_async
        scan_id = f"sched_{str(uuid.uuid4())[:6]}"
        run_scan_async(scan_id, url, report_dir)
        with _schedules_lock:
            if schedule_id in _schedules:
                _schedules[schedule_id]["last_run"] = datetime.utcnow().isoformat()
                _schedules[schedule_id]["last_scan_id"] = scan_id
    except Exception as e:
        print(f"[scheduler] Error running scheduled scan {schedule_id}: {e}")


def add_schedule(schedule_id: str, url: str, cron_expr: str, report_dir: str) -> bool:
    """Add a new scheduled scan. cron_expr format: 'minute hour day_of_week' e.g. '0 2 mon'"""
    if not _SCHEDULER_AVAILABLE:
        return False
    try:
        parts = cron_expr.strip().split()
        if len(parts) == 3:
            minute, hour, day_of_week = parts
        elif len(parts) == 5:
            minute, hour, _, _, day_of_week = parts
        else:
            return False
        trigger = CronTrigger(minute=minute, hour=hour, day_of_week=day_of_week)
        _scheduler.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            args=[schedule_id, url, report_dir],
            id=schedule_id,
            replace_existing=True,
        )
        with _schedules_lock:
            _schedules[schedule_id] = {
                "id": schedule_id, "url": url, "cron": cron_expr,
                "created_at": datetime.utcnow().isoformat(),
                "last_run": None, "last_scan_id": None,
            }
        return True
    except Exception as e:
        print(f"[scheduler] add_schedule error: {e}")
        return False


def remove_schedule(schedule_id: str) -> bool:
    if not _SCHEDULER_AVAILABLE:
        return False
    try:
        _scheduler.remove_job(schedule_id)
        with _schedules_lock:
            _schedules.pop(schedule_id, None)
        return True
    except Exception:
        return False


def list_schedules() -> list:
    with _schedules_lock:
        return list(_schedules.values())


def start():
    if _SCHEDULER_AVAILABLE and not _scheduler.running:
        _scheduler.start()
