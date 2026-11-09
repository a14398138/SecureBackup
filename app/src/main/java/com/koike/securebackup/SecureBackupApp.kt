package com.koike.securebackup

import android.app.Application
import androidx.work.Configuration

/**
 * Supplies the WorkManager configuration so WorkManager initializes lazily
 * on first use (inside a guarded call) instead of during process startup.
 * The default androidx.startup initializer is removed in the manifest:
 * v1.6/v1.6.1 crashed at launch on the user's device, and the only startup
 * delta from the last working version was WorkManagerInitializer.
 */
class SecureBackupApp : Application(), Configuration.Provider {
    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().build()
}
