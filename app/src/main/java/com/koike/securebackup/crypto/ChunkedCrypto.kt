package com.koike.securebackup.crypto

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Chunked AES-256-GCM stream format ("MBK1").
 *
 * Layout:
 *   magic "MBK1" (4) | version (1) | salt (16) | noncePrefix (8) | plainSize (8, BE)
 *   then ceil(plainSize / CHUNK) chunks. Chunk i is AES-GCM encrypted with
 *   nonce = noncePrefix || int32BE(i); each chunk's ciphertext carries its
 *   own 16-byte GCM tag, so tampering with any chunk is detected and large
 *   files never need to be held in memory.
 *
 * Buffers and Cipher instances are reused through ThreadLocals so the chunk
 * loops allocate nothing per chunk.
 */
object ChunkedCrypto {
    const val CHUNK = 1 shl 20 // 1 MiB plaintext per chunk
    private const val TAG_BITS = 128
    private const val TAG_BYTES = TAG_BITS / 8
    private val MAGIC = byteArrayOf('M'.code.toByte(), 'B'.code.toByte(), 'K'.code.toByte(), '1'.code.toByte())
    const val HEADER_SIZE = 4 + 1 + 16 + 8 + 8
    const val DEFAULT_ITERATIONS = 600_000

    /** Byte offset of the plainSize field inside the MBK1 header. */
    const val SIZE_FIELD_OFFSET = 29

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

    /** Salt embedded in the first bytes of an encrypted stream (needs >= 21 bytes). */
    fun saltOf(headerBytes: ByteArray): ByteArray {
        require(headerBytes.size >= 21 && MAGIC.indices.all { headerBytes[it] == MAGIC[it] }) {
            "not an MBK1 stream"
        }
        return headerBytes.copyOfRange(5, 21)
    }

    private fun chunkNonce(prefix: ByteArray, index: Int): ByteArray {
        val nonce = ByteArray(12)
        prefix.copyInto(nonce, 0, 0, 8)
        ByteBuffer.wrap(nonce, 8, 4).putInt(index)
        return nonce
    }

    fun encrypt(input: InputStream, output: OutputStream, key: SecretKeySpec, salt: ByteArray, plainSize: Long) {
        require(salt.size == 16) { "salt must be 16 bytes" }
        val noncePrefix = ByteArray(8).also { random.nextBytes(it) }
        val header = ByteBuffer.allocate(HEADER_SIZE)
        header.put(MAGIC)
        header.put(1)
        header.put(salt)
        header.put(noncePrefix)
        header.putLong(plainSize)
        output.write(header.array())

        val cipher = cipher()
        val buf = plainBuf()
        val outBuf = cipherBuf()
        var remaining = plainSize
        var index = 0
        while (remaining > 0) {
            val want = minOf(remaining, CHUNK.toLong()).toInt()
            val got = readFully(input, buf, want)
            check(got == want) { "source shrank while encrypting" }
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, chunkNonce(noncePrefix, index)))
            val outLen = cipher.doFinal(buf, 0, got, outBuf, 0)
            output.write(outBuf, 0, outLen)
            remaining -= got
            index++
        }
        output.flush()
    }

    /** Decrypts a full MBK1 stream. Returns the plaintext size written. Throws on tampering. */
    fun decrypt(input: InputStream, output: OutputStream, key: SecretKeySpec): Long {
        val size = decryptStreaming(input, key) { _, bytes, len -> output.write(bytes, 0, len) }
        output.flush()
        return size
    }

    /**
     * Decrypts chunk by chunk, reporting each plaintext chunk with its absolute
     * offset in the plaintext. The byte array passed to [sink] is a shared
     * buffer and is only valid during the call. Every consumed chunk's GCM
     * tag is verified.
     */
    fun decryptStreaming(
        input: InputStream,
        key: SecretKeySpec,
        sink: (plainOffset: Long, bytes: ByteArray, length: Int) -> Unit
    ): Long {
        val header = ByteArray(HEADER_SIZE)
        check(readFully(input, header, HEADER_SIZE) == HEADER_SIZE) { "truncated header" }
        require(MAGIC.indices.all { header[it] == MAGIC[it] } && header[4].toInt() == 1) { "not an MBK1 stream" }
        val noncePrefix = header.copyOfRange(21, 29)
        val plainSize = ByteBuffer.wrap(header, 29, 8).long

        val cipher = cipher()
        val buf = cipherBuf()
        val plain = plainBuf()
        var remaining = plainSize
        var index = 0
        var offset = 0L
        while (remaining > 0) {
            val plainLen = minOf(remaining, CHUNK.toLong()).toInt()
            val cipherLen = plainLen + TAG_BYTES
            check(readFully(input, buf, cipherLen) == cipherLen) { "truncated chunk $index" }
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, chunkNonce(noncePrefix, index)))
            val outLen = cipher.doFinal(buf, 0, cipherLen, plain, 0) // AEADBadTagException if tampered
            sink(offset, plain, outLen)
            offset += outLen
            remaining -= plainLen
            index++
        }
        return plainSize
    }

    /** Decrypts only the plaintext range [offset, offset+len) of an MBK1 stream. */
    fun decryptRange(input: InputStream, key: SecretKeySpec, offset: Long, len: Long, output: OutputStream) {
        require(offset >= 0 && len >= 0) { "negative range" }
        val end = offset + len
        decryptStreaming(input, key) { segOff, bytes, segLen ->
            val segEnd = segOff + segLen
            if (segEnd > offset && segOff < end) {
                val from = maxOf(0L, offset - segOff).toInt()
                val to = minOf(segLen.toLong(), end - segOff).toInt()
                output.write(bytes, from, to - from)
            }
        }
        output.flush()
    }

    fun encryptToBytes(plain: ByteArray, key: SecretKeySpec, salt: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        encrypt(java.io.ByteArrayInputStream(plain), out, key, salt, plain.size.toLong())
        return out.toByteArray()
    }

    fun decryptBytes(data: ByteArray, key: SecretKeySpec): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        decrypt(java.io.ByteArrayInputStream(data), out, key)
        return out.toByteArray()
    }

    private fun readFully(input: InputStream, buf: ByteArray, len: Int): Int {
        var read = 0
        while (read < len) {
            val n = input.read(buf, read, len - read)
            if (n < 0) break
            read += n
        }
        return read
    }
}

/**
 * Incremental MBK1 encryptor for streams whose total size is not known upfront
 * (used to build "pack" archives of many small files). The header is written
 * with a placeholder size; after [close], the caller patches the 8-byte size
 * field at [ChunkedCrypto.SIZE_FIELD_OFFSET] with [plainBytes] (the output
 * must be a seekable file). Chunking and authentication are identical to
 * [ChunkedCrypto.encrypt].
 */
class ChunkedEncryptor(
    private val out: OutputStream,
    private val key: SecretKeySpec,
    salt: ByteArray
) {
    private val noncePrefix = ByteArray(8).also { ChunkedCrypto.random.nextBytes(it) }
    private val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private val buf = ByteArray(ChunkedCrypto.CHUNK)
    private val outBuf = ByteArray(ChunkedCrypto.CHUNK + 16)
    private var bufLen = 0
    private var index = 0
    var plainBytes: Long = 0
        private set

    init {
        require(salt.size == 16) { "salt must be 16 bytes" }
        val header = ByteBuffer.allocate(ChunkedCrypto.HEADER_SIZE)
        header.put(byteArrayOf('M'.code.toByte(), 'B'.code.toByte(), 'K'.code.toByte(), '1'.code.toByte()))
        header.put(1)
        header.put(salt)
        header.put(noncePrefix)
        header.putLong(0) // placeholder, patched by the caller after close()
        out.write(header.array())
    }

    fun write(b: ByteArray, off: Int, len: Int) {
        var pos = off
        var remaining = len
        while (remaining > 0) {
            val n = minOf(remaining, ChunkedCrypto.CHUNK - bufLen)
            b.copyInto(buf, bufLen, pos, pos + n)
            bufLen += n
            pos += n
            remaining -= n
            plainBytes += n
            if (bufLen == ChunkedCrypto.CHUNK) flushChunk()
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

    private fun flushChunk() {
        if (bufLen == 0) return
        val nonce = ByteArray(12)
        noncePrefix.copyInto(nonce, 0, 0, 8)
        ByteBuffer.wrap(nonce, 8, 4).putInt(index)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        val outLen = cipher.doFinal(buf, 0, bufLen, outBuf, 0)
        out.write(outBuf, 0, outLen)
        bufLen = 0
        index++
    }

    fun close() {
        flushChunk()
        out.flush()
    }
}
