package com.koike.securebackup

import com.koike.securebackup.data.BackupReminder
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupReminderTest {

    private val day = 24L * 60 * 60 * 1000
    private val t0 = 1_700_000_000_000L

    @Test
    fun notDueBeforeAWeek() {
        assertFalse(BackupReminder.isDue(t0, t0 + 6 * day))
        assertFalse(BackupReminder.isDue(t0, t0 + BackupReminder.INTERVAL_MS - 1))
    }

    @Test
    fun dueAtExactlyAWeekAndAfter() {
        assertTrue(BackupReminder.isDue(t0, t0 + BackupReminder.INTERVAL_MS))
        assertTrue(BackupReminder.isDue(t0, t0 + 30 * day))
    }

    @Test
    fun neverBackedUpIsNotDue() {
        // 0 means "no record": the clock is seeded at schedule time instead.
        assertFalse(BackupReminder.isDue(0L, t0 + 365 * day))
    }
}
