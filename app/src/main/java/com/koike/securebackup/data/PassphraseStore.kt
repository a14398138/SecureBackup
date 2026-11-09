package com.koike.securebackup.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores the passphrase on this device only, encrypted with a key held in the
 * Android Keystore (the key itself never leaves the Keystore). This trades
 * some security for convenience: anyone who can unlock this phone and open
 * the app can run backups/restores without typing the passphrase.
 */
object PassphraseStore {
    private const val PREFS = "secure_prefs"
    private const val VALUE_KEY = "passphrase_enc"
    private const val KEY_ALIAS = "fullbackup_passphrase_key"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun save(context: Context, passphrase: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ct = cipher.doFinal(passphrase.toByteArray(Charsets.UTF_8))
        val blob = cipher.iv + ct
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(VALUE_KEY, Base64.getEncoder().encodeToString(blob))
            .apply()
    }

    fun load(context: Context): String? {
        val stored = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(VALUE_KEY, null) ?: return null
        return try {
            val blob = Base64.getDecoder().decode(stored)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
            String(cipher.doFinal(blob.copyOfRange(12, blob.size)), Charsets.UTF_8)
        } catch (e: Exception) {
            null // key invalidated etc. — behave as if nothing was saved
        }
    }

    fun has(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).contains(VALUE_KEY)

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().remove(VALUE_KEY).apply()
    }
}
