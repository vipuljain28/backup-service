"""Automated Background Backup Job Scheduler."""

import logging
from typing import Dict, Any, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger("backup_service.scheduler")


class BackupScheduler:
    """Manages background automated cron executions for all configured client schedules."""

    def __init__(self, db_manager, run_callback):
        self.db = db_manager
        self.run_callback = run_callback
        self.scheduler = BackgroundScheduler(timezone="UTC")
        self._active_jobs: Dict[str, str] = {}  # schedule_id -> job_id

    def start(self):
        """Start background scheduler loop and load existing schedules."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("BackupScheduler started.")
            self.reload_schedules()

    def shutdown(self):
        """Stop background scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("BackupScheduler stopped.")

    def reload_schedules(self):
        """Query database for all enabled schedules and register jobs."""
        self.scheduler.remove_all_jobs()
        self._active_jobs.clear()

        with self.db.connection() as conn:
            cur = conn.execute(
                """
                SELECT s.id, s.client_id, s.name, s.cron_expression, c.client_id AS client_slug
                FROM backup_schedules s
                JOIN clients c ON s.client_id = c.id
                WHERE s.is_enabled = 1 AND c.is_active = 1
                """
            )
            schedules = cur.fetchall()

        for s in schedules:
            sched_id = s["id"]
            client_db_id = s["client_id"]
            cron_expr = s["cron_expression"].strip()

            try:
                # Expecting standard 5-part cron: min hour day month day_of_week
                parts = cron_expr.split()
                if len(parts) == 5:
                    minute, hour, day, month, day_of_week = parts
                    trigger = CronTrigger(
                        minute=minute, hour=hour, day=day,
                        month=month, day_of_week=day_of_week, timezone="UTC"
                    )
                else:
                    logger.warning("Invalid cron expression '%s' for schedule %d, skipping.", cron_expr, sched_id)
                    continue

                job = self.scheduler.add_job(
                    func=self.run_callback,
                    trigger=trigger,
                    args=[client_db_id],
                    id=f"sched_{sched_id}",
                    name=s["name"],
                    replace_existing=True
                )
                self._active_jobs[str(sched_id)] = job.id
                logger.info("Registered schedule '%s' (Cron: %s) for client ID %d", s["name"], cron_expr, client_db_id)

            except Exception as exc:
                logger.error("Failed to register schedule %d: %s", sched_id, exc)
