package com.koike.securebackup.data

import android.content.Context

/**
 * Tracks when the last backup completed and decides whether the weekly
 * reminder is due. The timestamp lives in app-private preferences; the
 * due-check itself is a pure function so it can be unit-tested.
 */
object BackupReminder {

    private const val PREFS = "backup_state"
    private const val KEY_LAST = "last_backup_completed_at"

    const val INTERVAL_MS = 7L * 24 * 60 * 60 * 1000

    fun lastBackupAt(context: Context): Long =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(KEY_LAST, 0L)

    fun recordBackupCompleted(context: Context, nowMs: Long = System.currentTimeMillis()) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putLong(KEY_LAST, nowMs).apply()
    }

    /**
     * Seeds the clock the first time the reminder is scheduled (e.g. right
     * after updating to the version that introduced it) so an existing user
     * is not nagged immediately; the first reminder comes a week later.
     */
    fun seedIfUnset(context: Context, nowMs: Long = System.currentTimeMillis()) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains(KEY_LAST)) {
            prefs.edit().putLong(KEY_LAST, nowMs).apply()
        }
    }

    fun isDue(lastMs: Long, nowMs: Long): Boolean =
        lastMs > 0 && nowMs - lastMs >= INTERVAL_MS
}
