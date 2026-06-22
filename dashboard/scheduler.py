"""APScheduler-based scan scheduler for AutoPenTest dashboard."""
import os, json, threading, logging
from datetime import datetime

_schedules: dict = {}  # schedule_id -> schedule_config
_schedules_lock = threading.Lock()

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from pytz import timezone as tz
    
    # Use UTC+8 timezone (Malaysia/Singapore)
    LOCAL_TZ = tz('Asia/Kuala_Lumpur')
    _scheduler = BackgroundScheduler(timezone=LOCAL_TZ, daemon=True)
    _SCHEDULER_AVAILABLE = True
except ImportError:
    _scheduler = None
    _SCHEDULER_AVAILABLE = False
    LOCAL_TZ = None


def _run_scheduled_scan(schedule_id: str, url: str, report_dir: str):
    """Execute a scheduled scan."""
    try:
        import uuid, os, time
        from scanner_runner import run_scan_async, SCANS, SCANS_LOCK
        scan_id = f"sched_{str(uuid.uuid4())[:6]}"
        logger.info(f"[scheduler] RUNNING SCAN: {schedule_id} → {url}")
        
        # Set scan_id immediately when scan starts (for View button)
        with _schedules_lock:
            if schedule_id in _schedules:
                _schedules[schedule_id]["last_scan_id"] = scan_id
                logger.info(f"[scheduler] Scan started: {scan_id}, last_scan_id set")
        
        # Start the scan
        run_scan_async(scan_id, url, report_dir)
        
        # Now wait for scan to complete and check if report was generated
        max_wait = 300  # Wait up to 5 minutes for scan to complete
        start_time = time.time()
        report_ready = False
        
        while time.time() - start_time < max_wait:
            with SCANS_LOCK:
                if scan_id in SCANS and SCANS[scan_id].get("status") == "complete":
                    report_ready = True
                    break
            time.sleep(5)  # Check every 5 seconds
        
        with _schedules_lock:
            if schedule_id in _schedules:
                # Use the same timezone as the scheduler for consistency
                now = datetime.now(LOCAL_TZ).isoformat() if LOCAL_TZ else datetime.now().isoformat()
                _schedules[schedule_id]["last_run"] = now
                _schedules[schedule_id]["report_ready"] = report_ready
                logger.info(f"[scheduler] Scan completed: {scan_id}, report_ready={report_ready}, last_run updated to {now}")
    except Exception as e:
        logger.error(f"[scheduler] Error running scheduled scan {schedule_id}: {e}", exc_info=True)


def add_schedule(schedule_id: str, url: str, cron_expr: str, report_dir: str, original_format: str = None) -> bool:
    """Add a new scheduled scan. cron_expr format: '0 8 * * *' (5-part cron, with LOCAL_TZ)"""
    if not _SCHEDULER_AVAILABLE:
        logger.error("[scheduler] Scheduler not available")
        return False
    try:
        parts = cron_expr.strip().split()
        # Standard 5-part cron: minute hour day_of_month month day_of_week
        if len(parts) == 5:
            minute, hour, day_of_month, month, day_of_week = parts
            trigger = CronTrigger(minute=minute, hour=hour, day_of_week=day_of_week, timezone=LOCAL_TZ)
        else:
            logger.error(f"[scheduler] Invalid cron format: {cron_expr} (parts: {len(parts)})")
            return False
        
        job = _scheduler.add_job(
            _run_scheduled_scan,
            trigger=trigger,
            args=[schedule_id, url, report_dir],
            id=schedule_id,
            replace_existing=True,
            name=f"Scan {schedule_id}: {url}"
        )
        
        with _schedules_lock:
            _schedules[schedule_id] = {
                "id": schedule_id, 
                "url": url, 
                "cron": cron_expr,
                "display_format": original_format or cron_expr,  # Store human-readable format
                "created_at": (datetime.now(LOCAL_TZ).isoformat() if LOCAL_TZ else datetime.now().isoformat()),
                "last_run": None, 
                "last_scan_id": None,
                "report_ready": False,  # Initialize as not ready
            }
        
        logger.info(f"[scheduler] ✓ Added schedule {schedule_id}: {url} at {cron_expr} ({LOCAL_TZ})")
        logger.info(f"[scheduler] Next run: {job.next_run_time}")
        return True
    except Exception as e:
        logger.error(f"[scheduler] add_schedule error: {e}", exc_info=True)
        return False


def remove_schedule(schedule_id: str) -> bool:
    if not _SCHEDULER_AVAILABLE:
        return False
    try:
        _scheduler.remove_job(schedule_id)
        with _schedules_lock:
            _schedules.pop(schedule_id, None)
        logger.info(f"[scheduler] Removed schedule {schedule_id}")
        return True
    except Exception as e:
        logger.error(f"[scheduler] Error removing schedule {schedule_id}: {e}")
        return False


def list_schedules() -> list:
    with _schedules_lock:
        return list(_schedules.values())


def get_scheduler_status() -> dict:
    """Get scheduler status for debugging"""
    if not _SCHEDULER_AVAILABLE or not _scheduler:
        return {"running": False, "jobs": 0}
    
    jobs_info = []
    for job in _scheduler.get_jobs():
        jobs_info.append({
            "id": job.id,
            "name": job.name,
            "next_run": str(job.next_run_time) if job.next_run_time else None
        })
    
    return {
        "running": _scheduler.running,
        "timezone": str(LOCAL_TZ),
        "jobs_count": len(jobs_info),
        "jobs": jobs_info
    }


def start():
    if _SCHEDULER_AVAILABLE and not _scheduler.running:
        _scheduler.start()
        logger.info(f"[scheduler] ✓ Scheduler started (timezone: {LOCAL_TZ})")
        logger.info(f"[scheduler] Status: {get_scheduler_status()}")
    else:
        if _scheduler:
            logger.info(f"[scheduler] Scheduler already running")

