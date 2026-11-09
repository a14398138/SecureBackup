package com.koike.securebackup.backup

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.koike.securebackup.MainActivity
import com.koike.securebackup.data.BackupReminder
import java.util.concurrent.TimeUnit

/**
 * Daily check: once a week has passed since the last completed backup,
 * post a reminder notification. Runs until the next backup resets the
 * clock, so a missed notification is repeated on later days.
 */
class BackupReminderWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val last = BackupReminder.lastBackupAt(applicationContext)
        if (BackupReminder.isDue(last, System.currentTimeMillis())) {
            postNotification()
        }
        return Result.success()
    }

    private fun postNotification() {
        val nm = applicationContext.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "バックアップのリマインド",
                    NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
        val tap = PendingIntent.getActivity(
            applicationContext, 0,
            Intent(applicationContext, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("暗号化バックアップ")
            .setContentText("前回のバックアップから1週間が経ちました。差分バックアップを回しておきましょう。")
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        nm.notify(NOTIF_ID, n)
    }

    companion object {
        private const val CHANNEL_ID = "backup_reminder"
        private const val NOTIF_ID = 2
        private const val WORK_NAME = "backup-reminder-weekly"

        fun schedule(context: Context) {
            // Never propagate: WorkManager availability problems must not
            // crash app startup.
            runCatching {
                BackupReminder.seedIfUnset(context)
                val request = PeriodicWorkRequestBuilder<BackupReminderWorker>(1, TimeUnit.DAYS)
                    .build()
                WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                    WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request
                )
            }
        }
    }
}
