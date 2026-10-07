"""Run durable scheduled local-to-Azure sync jobs outside web workers."""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

import app as cloud_app
from cloud_security_services import sync_local_files


logger = logging.getLogger("cloud_rdx.automation")


def claim_due_sync_job():
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    with cloud_app.database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        job = connection.execute(
            """
            SELECT id, interval_minutes
            FROM sync_jobs
            WHERE enabled = 1 AND next_run_at <= ?
            ORDER BY next_run_at, id
            LIMIT 1
            """,
            (now_text,),
        ).fetchone()
        if not job:
            return None
        run = connection.execute(
            """
            INSERT INTO sync_runs (job_id, started_at, status)
            VALUES (?, ?, 'running')
            """,
            (job["id"], now_text),
        )
        next_run = (now + timedelta(minutes=job["interval_minutes"])).isoformat()
        connection.execute(
            "UPDATE sync_jobs SET last_run_at = ?, next_run_at = ? WHERE id = ?",
            (now_text, next_run, job["id"]),
        )
        return run.lastrowid


def run_claimed_sync(run_id: int):
    if cloud_app.emergency_enabled("disable_sync_automation"):
        status = "skipped_emergency"
        summary = "Sync skipped because emergency automation controls are enabled."
        uploaded = unchanged = unstable = 0
    else:
        try:
            counts = sync_local_files(
                cloud_app.SHARED_FOLDER,
                os.getenv("CLOUD_RDX_SYNC_CONTAINER", "cloud-rdx-sync"),
            )
        except Exception as error:
            status = "failed"
            summary = f"Sync failed ({type(error).__name__}). Review worker logs."
            uploaded = unchanged = unstable = 0
            logger.error("Sync run %s failed (%s)", run_id, type(error).__name__)
        else:
            status = "success"
            uploaded = counts["uploaded"]
            unchanged = counts["unchanged"]
            unstable = counts["unstable"]
            summary = (
                f"Uploaded {uploaded}; already present {unchanged}; "
                f"changed during snapshot {unstable}."
            )

    finished_at = datetime.now(timezone.utc).isoformat()
    with cloud_app.database_connection() as connection:
        connection.execute(
            """
            UPDATE sync_runs
            SET finished_at = ?, status = ?, uploaded_count = ?,
                unchanged_count = ?, unstable_count = ?, summary = ?
            WHERE id = ? AND status = 'running'
            """,
            (
                finished_at, status, uploaded, unchanged, unstable,
                summary, run_id,
            ),
        )


def main():
    cloud_app.initialize_database()
    try:
        poll_seconds = max(
            5, min(300, int(os.getenv("CLOUD_RDX_SYNC_POLL_SECONDS", "15")))
        )
    except ValueError:
        raise RuntimeError("CLOUD_RDX_SYNC_POLL_SECONDS must be an integer") from None
    logger.info("Cloud Rdx sync worker started")
    while True:
        run_id = claim_due_sync_job()
        if run_id is not None:
            run_claimed_sync(run_id)
        else:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    main()

