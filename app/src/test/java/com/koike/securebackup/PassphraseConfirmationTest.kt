package com.koike.securebackup

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PassphraseConfirmationTest {

    @Test
    fun newSetRequiresMatchingConfirmation() {
        assertFalse(passphraseConfirmationOk(true, "hunter2x", "hunter2y"))
        assertFalse(passphraseConfirmationOk(true, "hunter2x", ""))
        assertTrue(passphraseConfirmationOk(true, "hunter2x", "hunter2x"))
    }

    @Test
    fun existingSetDoesNotNeedConfirmation() {
        // The engine checks the passphrase against the set before writing.
        assertTrue(passphraseConfirmationOk(false, "hunter2x", ""))
        assertTrue(passphraseConfirmationOk(false, "hunter2x", "different"))
    }
}
