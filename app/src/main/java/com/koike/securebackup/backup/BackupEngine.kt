package com.koike.securebackup.backup

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.os.SystemClock
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import com.koike.securebackup.crypto.ChunkedCrypto
import com.koike.securebackup.crypto.ChunkedEncryptor
import com.koike.securebackup.data.BackupMeta
import com.koike.securebackup.data.Manifest
import com.koike.securebackup.data.ManifestEntry
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.util.UUID
import javax.crypto.spec.SecretKeySpec

data class JobProgress(
    val running: Boolean = false,
    val kind: String = "", // "backup" | "restore"
    val phase: String = "",
    val current: String = "",
    val doneFiles: Int = 0,
    val totalFiles: Int = 0,
    val doneBytes: Long = 0,
    val totalBytes: Long = 0,
    val newFiles: Int = 0,
    val skippedFiles: Int = 0,
    val errors: List<String> = emptyList(),
    val summary: String? = null
)

object EngineState {
    val flow = MutableStateFlow(JobProgress())
    @Volatile var cancelRequested = false
}

/**
 * Backup layout inside the destination folder:
 *   BACKUP_META.json  plaintext set metadata (salt / KDF / passphrase check)
 *   manifest.enc      MBK1-encrypted JSON manifest
 *   f/<uuid>.enc      one MBK1 stream per large file
 *   f/pack-<uuid>.enc one MBK1 stream concatenating many small files;
 *                     manifest entries point into it as "pack-<uuid>.enc@offset:len"
 * Encryption is end-to-end on the device; the destination only sees ciphertext.
 *
 * Provider access goes through DocumentsContract with one cursor query per
 * folder listing (DocumentFile would re-query per element). Known files are
 * overwritten in place instead of delete+recreate.
 */
class BackupEngine(private val context: Context) {

    private val resolver get() = context.contentResolver

    companion object {
        private const val PACK_THRESHOLD = 4L * 1024 * 1024   // files smaller than this go into packs
        private const val PACK_TARGET = 48L * 1024 * 1024     // pack size before flushing
        private const val MANIFEST_EVERY = 200                // files between periodic manifest saves
        private const val IO_BUFFER = 256 * 1024
        private const val SMALL_BUFFER = 64 * 1024
        private const val PROGRESS_INTERVAL_MS = 150L
        private const val MIME_OCTET = "application/octet-stream"
    }

    // ---------- DocumentsContract access layer ----------

    private class TreeAccess(private val resolver: ContentResolver, val treeUri: Uri) {
        val rootDocId: String = DocumentsContract.getTreeDocumentId(treeUri)

        data class Child(val docId: String, val name: String, val mime: String, val uri: Uri) {
            val isDir: Boolean get() = mime == DocumentsContract.Document.MIME_TYPE_DIR
        }

        fun docUri(docId: String): Uri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)

        /** One cursor query for the whole folder. */
        fun childrenMap(docId: String): MutableMap<String, Child> {
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
            val map = mutableMapOf<String, Child>()
            resolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE
                ),
                null, null, null
            )?.use { c ->
                val iId = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val iName = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val iMime = c.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_MIME_TYPE)
                while (c.moveToNext()) {
                    val id = c.getString(iId) ?: continue
                    val name = c.getString(iName) ?: continue
                    map[name] = Child(id, name, c.getString(iMime) ?: "", docUri(id))
                }
            }
            return map
        }

        fun create(parentDocId: String, mime: String, name: String): Child {
            val uri = DocumentsContract.createDocument(resolver, docUri(parentDocId), mime, name)
                ?: throw IllegalStateException("ドキュメントを作成できません: $name")
            return Child(DocumentsContract.getDocumentId(uri), name, mime, uri)
        }

        fun delete(child: Child): Boolean =
            try { DocumentsContract.deleteDocument(resolver, child.uri) } catch (e: Exception) { false }
    }

    private fun openIn(uri: Uri): InputStream =
        BufferedInputStream(resolver.openInputStream(uri)!!, SMALL_BUFFER)

    private fun openOut(uri: Uri): OutputStream =
        BufferedOutputStream(resolver.openOutputStream(uri, "wt")!!, IO_BUFFER)

    private fun readText(child: TreeAccess.Child): String =
        openIn(child.uri).use { it.readBytes().toString(Charsets.UTF_8) }

    /** Overwrites [existing] in place when possible; falls back to delete+create. */
    private fun writeChild(
        tree: TreeAccess,
        parentDocId: String,
        parentMap: MutableMap<String, TreeAccess.Child>,
        name: String,
        mime: String,
        write: (OutputStream) -> Unit
    ): TreeAccess.Child {
        val existing = parentMap[name]
        if (existing != null) {
            try {
                openOut(existing.uri).use(write)
                return existing
            } catch (e: Exception) {
                tree.delete(existing)
                parentMap.remove(name)
            }
        }
        val child = tree.create(parentDocId, mime, name)
        parentMap[name] = child
        openOut(child.uri).use(write)
        return child
    }

    // ---------- set metadata / manifest ----------

    private class SetContext(
        val tree: TreeAccess,
        val rootMap: MutableMap<String, TreeAccess.Child>,
        val meta: BackupMeta,
        val key: SecretKeySpec,
        val manifest: Manifest,
        val manifestExisted: Boolean,
        val fDir: TreeAccess.Child,
        val fMap: MutableMap<String, TreeAccess.Child>
    )

    private fun openSet(treeUri: Uri, passphrase: CharArray, create: Boolean): SetContext {
        val tree = TreeAccess(resolver, treeUri)
        val rootMap = tree.childrenMap(tree.rootDocId)

        val metaChild = rootMap["BACKUP_META.json"]
        val meta: BackupMeta
        val key: SecretKeySpec
        if (metaChild != null) {
            meta = BackupMeta.fromJson(readText(metaChild))
            key = ChunkedCrypto.deriveKey(passphrase, meta.salt, meta.iterations)
            val plain = try {
                ChunkedCrypto.decryptBytes(meta.check, key)
            } catch (e: Exception) {
                throw IllegalStateException("パスフレーズが違います（このバックアップのものではありません）")
            }
            check(plain.contentEquals(BackupMeta.CHECK_PLAIN)) {
                "パスフレーズが違います（このバックアップのものではありません）"
            }
        } else {
            check(create) { "BACKUP_META.json が見つかりません（バックアップフォルダではありません）" }
            val salt = ChunkedCrypto.newSalt()
            key = ChunkedCrypto.deriveKey(passphrase, salt, ChunkedCrypto.DEFAULT_ITERATIONS)
            meta = BackupMeta(
                iterations = ChunkedCrypto.DEFAULT_ITERATIONS,
                salt = salt,
                check = ChunkedCrypto.encryptToBytes(BackupMeta.CHECK_PLAIN, key, salt),
                createdAt = System.currentTimeMillis()
            )
            writeChild(tree, tree.rootDocId, rootMap, "BACKUP_META.json", "application/json") { out ->
                out.write(meta.toJson().toByteArray(Charsets.UTF_8))
            }
        }

        var manifest = Manifest()
        var manifestExisted = false
        val manifestChild = rootMap["manifest.enc"]
        if (manifestChild != null) {
            try {
                val out = ByteArrayOutputStream()
                openIn(manifestChild.uri).use { ChunkedCrypto.decrypt(it, out, key) }
                manifest = Manifest.fromJson(out.toByteArray().toString(Charsets.UTF_8))
                manifestExisted = true
            } catch (e: Exception) {
                manifest = Manifest() // unreadable manifest: start fresh rather than aborting
            }
        }

        var fDir = rootMap["f"]?.takeIf { it.isDir }
        if (fDir == null) {
            check(create) { "f フォルダが見つかりません" }
            fDir = tree.create(tree.rootDocId, DocumentsContract.Document.MIME_TYPE_DIR, "f")
            rootMap["f"] = fDir
        }
        val fMap = tree.childrenMap(fDir.docId)
        return SetContext(tree, rootMap, meta, key, manifest, manifestExisted, fDir, fMap)
    }

    private fun saveManifest(set: SetContext) {
        val bytes = set.manifest.toJson().toByteArray(Charsets.UTF_8)
        writeChild(set.tree, set.tree.rootDocId, set.rootMap, "manifest.enc", MIME_OCTET) { out ->
            ChunkedCrypto.encrypt(java.io.ByteArrayInputStream(bytes), out, set.key, set.meta.salt, bytes.size.toLong())
        }
    }

    /** Maps a SAF tree uri for the primary volume to an absolute path (no canonicalization). */
    private fun treeLocalPath(treeUri: Uri, storageRoot: File): String? = try {
        val docId = DocumentsContract.getTreeDocumentId(treeUri)
        if (docId.startsWith("primary:")) {
            val rel = docId.removePrefix("primary:").trim('/')
            if (rel.isEmpty()) storageRoot.absolutePath else File(storageRoot, rel).absolutePath
        } else null
    } catch (e: Exception) {
        null
    }

    // ---------- progress (throttled) ----------

    private class ProgressReporter(private var p: JobProgress) {
        private var lastPush = 0L
        fun update(transform: (JobProgress) -> JobProgress, errors: List<String>, force: Boolean = false) {
            p = transform(p).copy(errors = errors)
            push(force)
        }
        fun push(force: Boolean = false) {
            val now = SystemClock.elapsedRealtime()
            if (force || now - lastPush >= PROGRESS_INTERVAL_MS) {
                lastPush = now
                EngineState.flow.value = p
            }
        }
        fun finish(final: JobProgress) {
            EngineState.flow.value = final
        }
        val current: JobProgress get() = p
    }

    // ---------- backup ----------

    private data class ScannedFile(val file: File, val rel: String, val size: Long, val mtime: Long)

    fun runBackup(destTreeUri: Uri, passphrase: CharArray) {
        EngineState.cancelRequested = false
        val reporter = ProgressReporter(JobProgress(running = true, kind = "backup", phase = "準備中"))
        reporter.push(force = true)
        val errors = mutableListOf<String>()
        try {
            val rootDoc = DocumentFile.fromTreeUri(context, destTreeUri)
                ?: throw IllegalStateException("保存先フォルダを開けません")
            check(rootDoc.exists() && rootDoc.canWrite()) { "保存先フォルダに書き込めません" }

            val set = openSet(destTreeUri, passphrase, create = true)
            val manifest = set.manifest
            val oldSkippedDirs = manifest.skippedDirs

            // scan the whole shared-storage area, stat-ing each file exactly once
            reporter.update({ it.copy(phase = "ファイルを数えています") }, errors, force = true)
            val storageRoot = Environment.getExternalStorageDirectory()
            val excludePath = treeLocalPath(destTreeUri, storageRoot)
            val allFiles = mutableListOf<ScannedFile>()
            val skippedDirs = mutableListOf<String>()
            storageRoot.walkTopDown()
                .onEnter { dir -> excludePath == null || dir.absolutePath != excludePath }
                .onFail { f, _ -> skippedDirs += f.path }
                .forEach {
                    if (it.isFile) {
                        allFiles += ScannedFile(
                            it,
                            it.relativeTo(storageRoot).invariantSeparatorsPath,
                            it.length(),
                            it.lastModified()
                        )
                    }
                }
            manifest.skippedDirs = skippedDirs
            val totalBytes = allFiles.sumOf { it.size }
            val totalFiles = allFiles.size

            var doneBytes = 0L
            var doneFiles = 0
            var newCount = 0
            var skipCount = 0
            var sinceSave = 0
            var dirty = false

            // ---- pack builder state (small files concatenated into one MBK1 stream) ----
            var packTemp: File? = null
            var packOut: FileOutputStream? = null
            var packEnc: ChunkedEncryptor? = null
            var packName: String? = null
            var packBytes = 0L
            val packPending = mutableListOf<ManifestEntry>()

            fun discardPack() {
                try { packOut?.close() } catch (_: Exception) {}
                packTemp?.delete()
                packTemp = null; packOut = null; packEnc = null; packName = null
                packBytes = 0; packPending.clear()
            }

            fun flushPack() {
                val enc = packEnc ?: return
                val temp = packTemp!!
                val name = packName!!
                enc.close()
                packOut?.close()
                RandomAccessFile(temp, "rw").use { raf ->
                    raf.seek(ChunkedCrypto.SIZE_FIELD_OFFSET.toLong())
                    raf.writeLong(enc.plainBytes)
                }
                val dest = set.fMap[name] ?: set.tree.create(set.fDir.docId, MIME_OCTET, name)
                    .also { set.fMap[name] = it }
                FileInputStream(temp).use { ins -> openOut(dest.uri).use { out -> ins.copyTo(out, IO_BUFFER) } }
                for (e in packPending) manifest.files[e.path] = e
                dirty = true
                discardPack()
                try { saveManifest(set); dirty = false; sinceSave = 0 } catch (_: Exception) {}
            }

            fun safeFlushPack() {
                if (packEnc == null) return
                val pendingSnapshot = packPending.toList()
                val nameSnapshot = packName
                try {
                    flushPack()
                } catch (e: Exception) {
                    errors += "パック保存失敗 ($nameSnapshot): ${e.message ?: e.javaClass.simpleName}"
                    for (pe in pendingSnapshot) {
                        manifest.files[pe.path] = pe.copy(ok = false, error = "パック保存失敗")
                    }
                    dirty = true
                    discardPack()
                }
            }

            try {
                for (scanned in allFiles) {
                    if (EngineState.cancelRequested) throw InterruptedException("ユーザーにより中止")
                    val file = scanned.file
                    val rel = scanned.rel
                    val prev = manifest.files[rel]
                    if (prev != null && prev.ok && prev.size == scanned.size && prev.mtime == scanned.mtime) {
                        skipCount++
                    } else if (scanned.size < PACK_THRESHOLD) {
                        try {
                            val bytes = FileInputStream(file).use { it.readBytes() }
                            if (packEnc == null) {
                                packTemp = File.createTempFile("pack", ".tmp", context.cacheDir)
                                packOut = FileOutputStream(packTemp)
                                packEnc = ChunkedEncryptor(packOut!!, set.key, set.meta.salt)
                                packName = "pack-" + UUID.randomUUID().toString() + ".enc"
                                packBytes = 0
                            }
                            val offset = packBytes
                            packEnc!!.write(bytes, 0, bytes.size)
                            packBytes += bytes.size
                            packPending += ManifestEntry(
                                rel, bytes.size.toLong(), scanned.mtime,
                                "$packName@$offset:${bytes.size}", ok = true
                            )
                            newCount++
                            if (packBytes >= PACK_TARGET) safeFlushPack()
                        } catch (e: Exception) {
                            errors += "$rel: ${e.message ?: e.javaClass.simpleName}"
                            manifest.files[rel] = ManifestEntry(
                                rel, scanned.size, scanned.mtime,
                                prev?.enc ?: "", ok = false, error = e.message
                            )
                            dirty = true
                            discardPack() // offsets are no longer trustworthy
                        }
                    } else {
                        val requested = prev?.enc?.takeIf { '@' !in it } ?: (UUID.randomUUID().toString() + ".enc")
                        var destChild = set.fMap[requested]
                        val createdNow = destChild == null
                        try {
                            if (destChild == null) {
                                destChild = set.tree.create(set.fDir.docId, MIME_OCTET, requested)
                                set.fMap[requested] = destChild
                            }
                            FileInputStream(file).use { ins ->
                                openOut(destChild.uri).use { out ->
                                    ChunkedCrypto.encrypt(ins, out, set.key, set.meta.salt, scanned.size)
                                }
                            }
                            manifest.files[rel] = ManifestEntry(
                                rel, scanned.size, scanned.mtime, destChild.name, ok = true
                            )
                            newCount++
                            dirty = true
                        } catch (e: Exception) {
                            errors += "$rel: ${e.message ?: e.javaClass.simpleName}"
                            manifest.files[rel] = ManifestEntry(
                                rel, scanned.size, scanned.mtime,
                                destChild?.name ?: requested, ok = false, error = e.message
                            )
                            dirty = true
                            if (createdNow && destChild != null) {
                                set.tree.delete(destChild)
                                set.fMap.remove(requested)
                            }
                        }
                    }
                    doneBytes += scanned.size
                    doneFiles++
                    reporter.update(
                        {
                            it.copy(
                                phase = "バックアップ中", current = rel,
                                doneFiles = doneFiles, totalFiles = totalFiles,
                                doneBytes = doneBytes, totalBytes = totalBytes,
                                newFiles = newCount, skippedFiles = skipCount
                            )
                        },
                        errors
                    )
                    if (dirty && ++sinceSave >= MANIFEST_EVERY) {
                        sinceSave = 0
                        try { saveManifest(set); dirty = false } catch (_: Exception) {}
                    }
                }
                safeFlushPack()
            } catch (e: InterruptedException) {
                discardPack()
                try { saveManifest(set) } catch (_: Exception) {}
                throw e
            }

            // Skip the final manifest rewrite when literally nothing changed.
            val skippedDirsChanged = skippedDirs != oldSkippedDirs
            if (dirty || !set.manifestExisted || skippedDirsChanged) {
                reporter.update({ it.copy(phase = "目録を保存しています") }, errors, force = true)
                saveManifest(set)
            }
            reporter.finish(
                JobProgress(
                    running = false, kind = "backup", phase = "完了",
                    doneFiles = doneFiles, totalFiles = totalFiles,
                    doneBytes = doneBytes, totalBytes = totalBytes,
                    newFiles = newCount, skippedFiles = skipCount,
                    errors = errors.toList(),
                    summary = "バックアップ完了: 新規・更新 ${newCount}件 / 変更なし ${skipCount}件 / エラー ${errors.size}件"
                )
            )
        } catch (e: InterruptedException) {
            reporter.finish(
                reporter.current.copy(
                    running = false, phase = "中止", errors = errors.toList(),
                    summary = "バックアップを中止しました（完了分は目録に保存済み。次回は続きから再開します）"
                )
            )
        } catch (e: Exception) {
            errors += "致命的エラー: ${e.message ?: e.javaClass.simpleName}"
            reporter.finish(
                reporter.current.copy(
                    running = false, phase = "エラー", errors = errors.toList(),
                    summary = "バックアップ失敗: ${e.message}"
                )
            )
        }
    }

    // ---------- restore ----------

    private interface DestSink {
        fun open(relPath: String): OutputStream
    }

    /** Fast path: the destination is a folder inside the shared storage — write plain files. */
    private class LocalDest(private val root: File) : DestSink {
        override fun open(relPath: String): OutputStream {
            val target = File(root, relPath)
            val canonRoot = root.canonicalPath
            require(target.canonicalPath.startsWith(canonRoot + File.separator)) { "不正なパス: $relPath" }
            target.parentFile?.mkdirs()
            return BufferedOutputStream(FileOutputStream(target), IO_BUFFER)
        }
    }

    /** SAF destination (e.g. a Google Drive folder), with per-folder child caches. */
    private inner class SafDest(private val tree: TreeAccess) : DestSink {
        private val caches = mutableMapOf<String, MutableMap<String, TreeAccess.Child>>()

        private fun childrenOf(docId: String): MutableMap<String, TreeAccess.Child> =
            caches.getOrPut(docId) { tree.childrenMap(docId) }

        override fun open(relPath: String): OutputStream {
            val parts = relPath.split('/')
            var dirId = tree.rootDocId
            for (seg in parts.dropLast(1)) {
                val kids = childrenOf(dirId)
                var next = kids[seg]
                if (next == null) {
                    next = tree.create(dirId, DocumentsContract.Document.MIME_TYPE_DIR, seg)
                    kids[seg] = next
                }
                dirId = next.docId
            }
            val kids = childrenOf(dirId)
            val name = parts.last()
            var leaf = kids[name]
            if (leaf == null) {
                leaf = tree.create(dirId, MIME_OCTET, name)
                kids[name] = leaf
            }
            return openOut(leaf.uri)
        }
    }

    fun runRestore(srcTreeUri: Uri, destTreeUri: Uri, passphrase: CharArray) {
        EngineState.cancelRequested = false
        val reporter = ProgressReporter(JobProgress(running = true, kind = "restore", phase = "準備中"))
        reporter.push(force = true)
        val errors = mutableListOf<String>()
        try {
            val set = openSet(srcTreeUri, passphrase, create = false)

            val storageRoot = Environment.getExternalStorageDirectory()
            val localPath = treeLocalPath(destTreeUri, storageRoot)
            val dest: DestSink = if (localPath != null) {
                LocalDest(File(localPath))
            } else {
                SafDest(TreeAccess(resolver, destTreeUri))
            }

            val entries = set.manifest.files.values.filter { it.ok }
            val totalBytes = entries.sumOf { it.size }
            val totalFiles = entries.size
            var doneBytes = 0L
            var doneFiles = 0
            var restored = 0

            fun bump(entry: ManifestEntry) {
                doneBytes += entry.size
                doneFiles++
                reporter.update(
                    {
                        it.copy(
                            phase = "復元中", current = entry.path,
                            doneFiles = doneFiles, totalFiles = totalFiles,
                            doneBytes = doneBytes, totalBytes = totalBytes
                        )
                    },
                    errors
                )
            }

            // single-file entries
            for (entry in entries.filter { '@' !in it.enc }) {
                if (EngineState.cancelRequested) throw InterruptedException("ユーザーにより中止")
                try {
                    val encChild = set.fMap[entry.enc]
                        ?: throw IllegalStateException("暗号化ファイルが見つかりません: ${entry.enc}")
                    openIn(encChild.uri).use { ins ->
                        dest.open(entry.path).use { out -> ChunkedCrypto.decrypt(ins, out, set.key) }
                    }
                    restored++
                } catch (e: Exception) {
                    if (e is InterruptedException) throw e
                    errors += "${entry.path}: ${e.message ?: e.javaClass.simpleName}"
                }
                bump(entry)
            }

            // packed entries: one decrypt pass per pack, slicing members out in offset order
            val packGroups = entries.filter { '@' in it.enc }.groupBy { it.enc.substringBefore('@') }
            for ((packName, membersRaw) in packGroups) {
                if (EngineState.cancelRequested) throw InterruptedException("ユーザーにより中止")
                data class Member(val entry: ManifestEntry, val offset: Long, val len: Long)
                val members = membersRaw.map { e ->
                    val range = e.enc.substringAfter('@').split(':')
                    Member(e, range[0].toLong(), range[1].toLong())
                }.sortedBy { it.offset }
                var completedInPack = 0
                try {
                    val packChild = set.fMap[packName]
                        ?: throw IllegalStateException("パックが見つかりません: $packName")
                    var idx = 0
                    var curOut: OutputStream? = null
                    fun closeCur() { try { curOut?.close() } catch (_: Exception) {}; curOut = null }
                    try {
                        openIn(packChild.uri).use { ins ->
                            ChunkedCrypto.decryptStreaming(ins, set.key) { segOff, bytes, segLen ->
                                var pos = segOff
                                var bOff = 0
                                val segEnd = segOff + segLen
                                while (pos < segEnd && idx < members.size) {
                                    val m = members[idx]
                                    if (pos < m.offset) {
                                        val skip = minOf(m.offset - pos, segEnd - pos)
                                        pos += skip; bOff += skip.toInt()
                                        continue
                                    }
                                    if (curOut == null) {
                                        curOut = dest.open(m.entry.path)
                                    }
                                    val n = minOf(m.offset + m.len - pos, segEnd - pos).toInt()
                                    if (n > 0) {
                                        curOut!!.write(bytes, bOff, n)
                                        pos += n; bOff += n
                                    }
                                    if (pos >= m.offset + m.len) {
                                        closeCur()
                                        idx++
                                        completedInPack = idx
                                        restored++
                                        bump(m.entry)
                                    }
                                }
                            }
                        }
                    } finally {
                        closeCur()
                    }
                    while (idx < members.size) {
                        errors += "${members[idx].entry.path}: パック内にデータが見つかりません"
                        bump(members[idx].entry)
                        idx++
                    }
                } catch (e: Exception) {
                    if (e is InterruptedException) throw e
                    for (m in members.drop(completedInPack)) {
                        errors += "${m.entry.path}: ${e.message ?: e.javaClass.simpleName}"
                        bump(m.entry)
                    }
                }
            }

            reporter.finish(
                JobProgress(
                    running = false, kind = "restore", phase = "完了",
                    doneFiles = doneFiles, totalFiles = totalFiles,
                    doneBytes = doneBytes, totalBytes = totalBytes,
                    errors = errors.toList(),
                    summary = "復元完了: ${restored}件 / エラー ${errors.size}件"
                )
            )
        } catch (e: InterruptedException) {
            reporter.finish(
                reporter.current.copy(
                    running = false, phase = "中止", errors = errors.toList(),
                    summary = "復元を中止しました"
                )
            )
        } catch (e: Exception) {
            errors += "致命的エラー: ${e.message ?: e.javaClass.simpleName}"
            reporter.finish(
                reporter.current.copy(
                    running = false, phase = "エラー", errors = errors.toList(),
                    summary = "復元失敗: ${e.message}"
                )
            )
        }
    }
}
