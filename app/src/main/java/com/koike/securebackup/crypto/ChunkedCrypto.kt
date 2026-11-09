package com.koike.securebackup.crypto

import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Chunked AES-256-GCM stream format.
 *
 * Current format "MBK2" (written by this version):
 *   magic "MBK2" (4) | version 2 (1) | salt (16) | noncePrefix (8)
 *   then one or more chunks. Every chunk except the last holds exactly CHUNK
 *   plaintext bytes; the last one holds 0..CHUNK bytes and is always present
 *   (an empty stream is a single empty final chunk). Chunk i is encrypted with
 *     nonce = noncePrefix || int32BE(i)
 *     AAD   = header (29) || int32BE(i) || finalFlag (1) || context (UTF-8)
 *   so the header cannot be altered, chunks cannot be reordered, the stream
 *   cannot be truncated at a chunk boundary (the new last chunk was sealed as
 *   non-final and fails authentication), and a stream cannot be swapped with
 *   another stream of the same set (each is bound to its own [context],
 *   typically the file name the manifest refers to).
 *
 * Legacy format "MBK1" (read only):
 *   magic "MBK1" (4) | version 1 (1) | salt (16) | noncePrefix (8) | plainSize (8, BE)
 *   with no AAD. Its plainSize is unauthenticated, so callers should compare
 *   the decrypted length with an authenticated expectation (the manifest).
 */
object ChunkedCrypto {
    const val CHUNK = 1 shl 20 // 1 MiB plaintext per chunk
    private const val TAG_BITS = 128
    const val TAG_BYTES = TAG_BITS / 8
    const val DEFAULT_ITERATIONS = 600_000

    private val MAGIC_V1 = "MBK1".toByteArray(Charsets.US_ASCII)
    private val MAGIC_V2 = "MBK2".toByteArray(Charsets.US_ASCII)
    private const val PREFIX_SIZE = 5 // magic + version byte

    /** Header size of the current (MBK2) format. */
    const val HEADER_SIZE = 4 + 1 + 16 + 8
    /** Header size of the legacy MBK1 format. */
    const val HEADER_SIZE_V1 = 4 + 1 + 16 + 8 + 8

    val random = SecureRandom() // thread-safe, shared

    private val cipherTl = ThreadLocal<Cipher>()
    private val plainBufTl = ThreadLocal<ByteArray>()
    private val cipherBufTl = ThreadLocal<ByteArray>()

    private fun cipher(): Cipher =
        cipherTl.get() ?: Cipher.getInstance("AES/GCM/NoPadding").also { cipherTl.set(it) }

    private fun plainBuf(): ByteArray =
        plainBufTl.get() ?: ByteArray(CHUNK).also { plainBufTl.set(it) }

    private fun cipherBuf(): ByteArray =
        cipherBufTl.get() ?: ByteArray(CHUNK + TAG_BYTES).also { cipherBufTl.set(it) }

    fun newSalt(): ByteArray = ByteArray(16).also { random.nextBytes(it) }

    fun deriveKey(passphrase: CharArray, salt: ByteArray, iterations: Int = DEFAULT_ITERATIONS): SecretKeySpec {
        val spec = PBEKeySpec(passphrase, salt, iterations, 256)
        try {
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    private fun hasMagic(bytes: ByteArray, magic: ByteArray) =
        bytes.size >= magic.size && magic.indices.all { bytes[it] == magic[it] }

    /** Salt embedded in the first bytes of an encrypted stream (needs >= 21 bytes). */
    fun saltOf(headerBytes: ByteArray): ByteArray {
        require(headerBytes.size >= 21 && (hasMagic(headerBytes, MAGIC_V1) || hasMagic(headerBytes, MAGIC_V2))) {
            "not an MBK stream"
        }
        return headerBytes.copyOfRange(5, 21)
    }

    internal fun chunkNonce(prefix: ByteArray, index: Int): ByteArray {
        val nonce = ByteArray(12)
        prefix.copyInto(nonce, 0, 0, 8)
        ByteBuffer.wrap(nonce, 8, 4).putInt(index)
        return nonce
    }

    /** AAD template: header || index(4) || final(1) || context. Index/final are patched per chunk. */
    internal fun aadTemplate(header: ByteArray, context: String): ByteArray {
        val ctx = context.toByteArray(Charsets.UTF_8)
        val aad = ByteArray(header.size + 5 + ctx.size)
        header.copyInto(aad, 0)
        ctx.copyInto(aad, header.size + 5)
        return aad
    }

    internal fun setChunkAad(aad: ByteArray, headerSize: Int, index: Int, final: Boolean) {
        ByteBuffer.wrap(aad, headerSize, 4).putInt(index)
        aad[headerSize + 4] = if (final) 1 else 0
    }

    internal fun newHeader(salt: ByteArray, noncePrefix: ByteArray): ByteArray {
        require(salt.size == 16) { "salt must be 16 bytes" }
        return ByteBuffer.allocate(HEADER_SIZE)
            .put(MAGIC_V2).put(2).put(salt).put(noncePrefix)
            .array()
    }

    /**
     * Encrypts exactly [plainSize] bytes of [input]. Fails if the source ends
     * early; bytes beyond [plainSize] are ignored.
     */
    fun encrypt(
        input: InputStream,
        output: OutputStream,
        key: SecretKeySpec,
        salt: ByteArray,
        plainSize: Long,
        context: String
    ) {
        val enc = ChunkedEncryptor(output, key, salt, context, cipher(), plainBuf(), cipherBuf())
        val tmp = ByteArray(64 * 1024)
        var remaining = plainSize
        while (remaining > 0) {
            val n = input.read(tmp, 0, minOf(remaining, tmp.size.toLong()).toInt())
            check(n >= 0) { "source shrank while encrypting" }
            enc.write(tmp, 0, n)
            remaining -= n
        }
        enc.close()
    }

    /** Decrypts a full stream. Returns the plaintext size written. Throws on tampering. */
    fun decrypt(input: InputStream, output: OutputStream, key: SecretKeySpec, context: String): Long {
        val size = decryptStreaming(input, key, context) { _, bytes, len -> output.write(bytes, 0, len) }
        output.flush()
        return size
    }

    /**
     * Decrypts chunk by chunk, reporting each plaintext chunk with its absolute
     * offset in the plaintext. The byte array passed to [sink] is a shared
     * buffer and is only valid during the call. Every chunk's GCM tag is
     * verified; for MBK2 streams truncation is detected as well.
     */
    fun decryptStreaming(
        input: InputStream,
        key: SecretKeySpec,
        context: String,
        sink: (plainOffset: Long, bytes: ByteArray, length: Int) -> Unit
    ): Long {
        val prefix = ByteArray(PREFIX_SIZE)
        if (readFully(input, prefix, PREFIX_SIZE) != PREFIX_SIZE) throw AEADBadTagException("truncated header")
        return when {
            hasMagic(prefix, MAGIC_V2) && prefix[4].toInt() == 2 -> decryptV2(prefix, input, key, context, sink)
            hasMagic(prefix, MAGIC_V1) && prefix[4].toInt() == 1 -> decryptV1(prefix, input, key, sink)
            else -> throw IllegalArgumentException("not an MBK stream")
        }
    }

    private fun decryptV2(
        prefix: ByteArray,
        rawInput: InputStream,
        key: SecretKeySpec,
        context: String,
        sink: (Long, ByteArray, Int) -> Unit
    ): Long {
        val header = prefix.copyOf(HEADER_SIZE)
        val rest = HEADER_SIZE - PREFIX_SIZE
        if (readFully(rawInput, header, rest, PREFIX_SIZE) != rest) throw AEADBadTagException("truncated header")
        val noncePrefix = header.copyOfRange(21, 29)
        val aad = aadTemplate(header, context)
        val input = PushbackInputStream(rawInput, 1)

        val cipher = cipher()
        val buf = cipherBuf()
        val plain = plainBuf()
        var index = 0
        var offset = 0L
        while (true) {
            val n = readFully(input, buf, CHUNK + TAG_BYTES)
            if (n < TAG_BYTES) throw AEADBadTagException("truncated stream (chunk $index)")
            val final = if (n < CHUNK + TAG_BYTES) {
                true
            } else {
                val next = input.read()
                if (next < 0) true else { input.unread(next); false }
            }
            check(index >= 0) { "too many chunks" }
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, chunkNonce(noncePrefix, index)))
            setChunkAad(aad, HEADER_SIZE, index, final)
            cipher.updateAAD(aad)
            val outLen = cipher.doFinal(buf, 0, n, plain, 0) // AEADBadTagException if tampered/truncated
            sink(offset, plain, outLen)
            offset += outLen
            index++
            if (final) return offset
        }
    }

    private fun decryptV1(
        prefix: ByteArray,
        input: InputStream,
        key: SecretKeySpec,
        sink: (Long, ByteArray, Int) -> Unit
    ): Long {
        val header = prefix.copyOf(HEADER_SIZE_V1)
        val rest = HEADER_SIZE_V1 - PREFIX_SIZE
        if (readFully(input, header, rest, PREFIX_SIZE) != rest) throw AEADBadTagException("truncated header")
        val noncePrefix = header.copyOfRange(21, 29)
        val plainSize = ByteBuffer.wrap(header, 29, 8).long
        require(plainSize >= 0) { "invalid MBK1 size" }

        val cipher = cipher()
        val buf = cipherBuf()
        val plain = plainBuf()
        var remaining = plainSize
        var index = 0
        var offset = 0L
        while (remaining > 0) {
            val plainLen = minOf(remaining, CHUNK.toLong()).toInt()
            val cipherLen = plainLen + TAG_BYTES
            if (readFully(input, buf, cipherLen) != cipherLen) throw AEADBadTagException("truncated chunk $index")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, chunkNonce(noncePrefix, index)))
            val outLen = cipher.doFinal(buf, 0, cipherLen, plain, 0)
            sink(offset, plain, outLen)
            offset += outLen
            remaining -= plainLen
            index++
        }
        return plainSize
    }

    /** Decrypts only the plaintext range [offset, offset+len) of a stream (the whole stream is still verified). */
    fun decryptRange(
        input: InputStream,
        key: SecretKeySpec,
        context: String,
        offset: Long,
        len: Long,
        output: OutputStream
    ) {
        require(offset >= 0 && len >= 0) { "negative range" }
        val end = offset + len
        decryptStreaming(input, key, context) { segOff, bytes, segLen ->
            val segEnd = segOff + segLen
            if (segEnd > offset && segOff < end) {
                val from = maxOf(0L, offset - segOff).toInt()
                val to = minOf(segLen.toLong(), end - segOff).toInt()
                output.write(bytes, from, to - from)
            }
        }
        output.flush()
    }

    fun encryptToBytes(plain: ByteArray, key: SecretKeySpec, salt: ByteArray, context: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        encrypt(java.io.ByteArrayInputStream(plain), out, key, salt, plain.size.toLong(), context)
        return out.toByteArray()
    }

    fun decryptBytes(data: ByteArray, key: SecretKeySpec, context: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        decrypt(java.io.ByteArrayInputStream(data), out, key, context)
        return out.toByteArray()
    }

    private fun readFully(input: InputStream, buf: ByteArray, len: Int, off: Int = 0): Int {
        var read = 0
        while (read < len) {
            val n = input.read(buf, off + read, len - read)
            if (n < 0) break
            read += n
        }
        return read
    }
}

/**
 * Incremental MBK2 encryptor for streams whose total size is not known
 * upfront (used directly for "pack" archives of many small files, and by
 * [ChunkedCrypto.encrypt]). A full chunk is only sealed once more data
 * arrives, so [close] always seals the true last chunk with the final flag.
 * Nothing needs to be patched afterwards.
 */
class ChunkedEncryptor internal constructor(
    private val out: OutputStream,
    private val key: SecretKeySpec,
    salt: ByteArray,
    context: String,
    private val cipher: Cipher,
    private val buf: ByteArray,
    private val outBuf: ByteArray
) {
    constructor(out: OutputStream, key: SecretKeySpec, salt: ByteArray, context: String) : this(
        out, key, salt, context,
        Cipher.getInstance("AES/GCM/NoPadding"),
        ByteArray(ChunkedCrypto.CHUNK),
        ByteArray(ChunkedCrypto.CHUNK + ChunkedCrypto.TAG_BYTES)
    )

    private val noncePrefix = ByteArray(8).also { ChunkedCrypto.random.nextBytes(it) }
    private val header = ChunkedCrypto.newHeader(salt, noncePrefix)
    private val aad = ChunkedCrypto.aadTemplate(header, context)
    private var bufLen = 0
    private var index = 0
    private var closed = false
    var plainBytes: Long = 0
        private set

    init {
        out.write(header)
    }

    fun write(b: ByteArray, off: Int, len: Int) {
        check(!closed) { "encryptor closed" }
        var pos = off
        var remaining = len
        while (remaining > 0) {
            // A full buffer is sealed as non-final only now that more data follows.
            if (bufLen == ChunkedCrypto.CHUNK) sealChunk(final = false)
            val n = minOf(remaining, ChunkedCrypto.CHUNK - bufLen)
            b.copyInto(buf, bufLen, pos, pos + n)
            bufLen += n
            pos += n
            remaining -= n
            plainBytes += n
        }
    }

    fun write(input: InputStream) {
        val tmp = ByteArray(256 * 1024)
        while (true) {
            val n = input.read(tmp)
            if (n < 0) break
            write(tmp, 0, n)
        }
    }

    private fun sealChunk(final: Boolean) {
        check(index >= 0) { "too many chunks" }
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, ChunkedCrypto.chunkNonce(noncePrefix, index)))
        ChunkedCrypto.setChunkAad(aad, ChunkedCrypto.HEADER_SIZE, index, final)
        cipher.updateAAD(aad)
        val outLen = cipher.doFinal(buf, 0, bufLen, outBuf, 0)
        out.write(outBuf, 0, outLen)
        bufLen = 0
        index++
    }

    /** Seals the final chunk. Must be called exactly once; the stream is invalid without it. */
    fun close() {
        if (closed) return
        sealChunk(final = true)
        closed = true
        out.flush()
    }
}
