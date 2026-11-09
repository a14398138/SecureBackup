package com.koike.securebackup.data

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/** Plaintext BACKUP_META.json stored at the root of a backup set. */
data class BackupMeta(
    val iterations: Int,
    val salt: ByteArray,
    val check: ByteArray, // MBK1-encrypted CHECK_PLAIN, proves the passphrase
    val createdAt: Long
) {
    fun toJson(): String {
        val enc = Base64.getEncoder()
        return JSONObject()
            .put("format", 1)
            .put("app", "com.koike.securebackup")
            .put("kdf", "PBKDF2WithHmacSHA256")
            .put("iterations", iterations)
            .put("salt", enc.encodeToString(salt))
            .put("check", enc.encodeToString(check))
            .put("createdAt", createdAt)
            .toString()
    }

    companion object {
        val CHECK_PLAIN = "FULLBACKUP-CHECK-V1".toByteArray(Charsets.UTF_8)

        /** Encryption context (AAD) the check block is bound to. */
        const val CHECK_CONTEXT = "check"

        fun fromJson(text: String): BackupMeta {
            val o = JSONObject(text)
            require(o.optInt("format", -1) == 1) { "unsupported backup format" }
            val dec = Base64.getDecoder()
            return BackupMeta(
                iterations = o.getInt("iterations"),
                salt = dec.decode(o.getString("salt")),
                check = dec.decode(o.getString("check")),
                createdAt = o.optLong("createdAt", 0)
            )
        }
    }
}

data class ManifestEntry(
    val path: String,     // path relative to the storage root, '/'-separated
    val size: Long,
    val mtime: Long,
    val enc: String,      // file name inside the "f" folder of the backup set
    val ok: Boolean,
    val error: String? = null
)

class Manifest {
    val files = LinkedHashMap<String, ManifestEntry>()
    var skippedDirs: List<String> = emptyList()

    /**
     * Save counter. The manifest is written alternately to two slots; on load
     * the readable slot with the highest seq wins, so an interrupted write
     * never destroys the last good manifest.
     */
    var seq: Long = 0

    /**
     * Names in the "f" folder that this manifest no longer references but the
     * previous manifest (in the other slot) may still reference. They are
     * deleted only after the next manifest has been saved successfully.
     */
    var trash: List<String> = emptyList()

    fun toJson(): String {
        val arr = JSONArray()
        for (e in files.values) {
            arr.put(
                JSONObject()
                    .put("path", e.path)
                    .put("size", e.size)
                    .put("mtime", e.mtime)
                    .put("enc", e.enc)
                    .put("ok", e.ok)
                    .put("error", e.error ?: JSONObject.NULL)
            )
        }
        return JSONObject()
            .put("version", 1)
            .put("updatedAt", System.currentTimeMillis())
            .put("seq", seq)
            .put("trash", JSONArray(trash))
            .put("skippedDirs", JSONArray(skippedDirs))
            .put("files", arr)
            .toString()
    }

    companion object {
        fun fromJson(text: String): Manifest {
            val o = JSONObject(text)
            val m = Manifest()
            val arr = o.optJSONArray("files") ?: JSONArray()
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                val entry = ManifestEntry(
                    path = e.getString("path"),
                    size = e.getLong("size"),
                    mtime = e.getLong("mtime"),
                    enc = e.getString("enc"),
                    ok = e.optBoolean("ok", true),
                    error = if (e.isNull("error")) null else e.optString("error")
                )
                m.files[entry.path] = entry
            }
            val sk = o.optJSONArray("skippedDirs")
            if (sk != null) {
                m.skippedDirs = (0 until sk.length()).map { sk.optString(it) }
            }
            m.seq = o.optLong("seq", 0)
            val tr = o.optJSONArray("trash")
            if (tr != null) {
                m.trash = (0 until tr.length()).map { tr.optString(it) }.filter { it.isNotEmpty() }
            }
            return m
        }
    }
}
