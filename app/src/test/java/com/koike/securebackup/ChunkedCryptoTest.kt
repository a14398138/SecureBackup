package com.koike.securebackup

import com.koike.securebackup.crypto.ChunkedCrypto
import com.koike.securebackup.crypto.ChunkedEncryptor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.Random
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class ChunkedCryptoTest {

    private val salt = ByteArray(16) { it.toByte() }
    private val key = ChunkedCrypto.deriveKey("test-passphrase".toCharArray(), salt, 10_000)
    private val ctx = "f/test.enc"
    private val chunkCipherLen = ChunkedCrypto.CHUNK + ChunkedCrypto.TAG_BYTES

    private fun encrypt(data: ByteArray, context: String = ctx): ByteArray {
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong(), context)
        return encOut.toByteArray()
    }

    private fun decrypt(enc: ByteArray, context: String = ctx): ByteArray =
        ChunkedCrypto.decryptBytes(enc, key, context)

    private fun roundTrip(data: ByteArray): ByteArray {
        val decOut = ByteArrayOutputStream()
        val size = ChunkedCrypto.decrypt(ByteArrayInputStream(encrypt(data)), decOut, key, ctx)
        assertEquals(data.size.toLong(), size)
        return decOut.toByteArray()
    }

    private fun random(size: Int, seed: Long) = ByteArray(size).also { Random(seed).nextBytes(it) }

    // ---------- round trips ----------

    @Test
    fun emptyFile() {
        assertArrayEquals(ByteArray(0), roundTrip(ByteArray(0)))
    }

    @Test
    fun smallFile() {
        val data = "hello backup".toByteArray(Charsets.UTF_8)
        assertArrayEquals(data, roundTrip(data))
    }

    @Test
    fun exactlyOneChunk() {
        val data = random(ChunkedCrypto.CHUNK, 42)
        assertArrayEquals(data, roundTrip(data))
        // a full chunk is the final chunk: no extra empty chunk follows
        assertEquals(ChunkedCrypto.HEADER_SIZE + chunkCipherLen, encrypt(data).size)
    }

    @Test
    fun exactMultipleOfChunks() {
        val data = random(ChunkedCrypto.CHUNK * 2, 43)
        assertArrayEquals(data, roundTrip(data))
    }

    @Test
    fun multiChunkWithRemainder() {
        val data = random(ChunkedCrypto.CHUNK * 2 + 12345, 7)
        assertArrayEquals(data, roundTrip(data))
    }

    // ---------- tampering ----------

    @Test
    fun tamperedCiphertextIsDetected() {
        val enc = encrypt(random(5000, 1))
        enc[ChunkedCrypto.HEADER_SIZE + 100] = (enc[ChunkedCrypto.HEADER_SIZE + 100] + 1).toByte()
        assertThrows(AEADBadTagException::class.java) { decrypt(enc) }
    }

    @Test
    fun tamperedLaterChunkIsDetected() {
        val enc = encrypt(random(ChunkedCrypto.CHUNK + 5000, 3))
        val idx = ChunkedCrypto.HEADER_SIZE + chunkCipherLen + 10 // inside chunk 1
        enc[idx] = (enc[idx] + 1).toByte()
        assertThrows(AEADBadTagException::class.java) { decrypt(enc) }
    }

    @Test
    fun tamperedHeaderIsDetected() {
        val enc = encrypt(random(5000, 4))
        enc[10] = (enc[10] + 1).toByte() // inside the salt field
        assertThrows(AEADBadTagException::class.java) { decrypt(enc) }
    }

    @Test
    fun truncationAtChunkBoundaryIsDetected() {
        val enc = encrypt(random(ChunkedCrypto.CHUNK * 3 + 100, 5))
        for (chunks in 1..3) {
            val cut = enc.copyOf(ChunkedCrypto.HEADER_SIZE + chunks * chunkCipherLen)
            assertThrows("cut after $chunks chunks", AEADBadTagException::class.java) { decrypt(cut) }
        }
    }

    @Test
    fun truncationOfExactMultipleIsDetected() {
        // the dangerous case: every remaining chunk is a full, valid-looking chunk
        val enc = encrypt(random(ChunkedCrypto.CHUNK * 2, 6))
        val cut = enc.copyOf(ChunkedCrypto.HEADER_SIZE + chunkCipherLen)
        assertThrows(AEADBadTagException::class.java) { decrypt(cut) }
    }

    @Test
    fun truncationInsideChunkIsDetected() {
        val enc = encrypt(random(ChunkedCrypto.CHUNK + 5000, 8))
        assertThrows(AEADBadTagException::class.java) { decrypt(enc.copyOf(enc.size - 1)) }
        assertThrows(AEADBadTagException::class.java) { decrypt(enc.copyOf(ChunkedCrypto.HEADER_SIZE + 1000)) }
    }

    @Test
    fun headerOnlyIsDetected() {
        val enc = encrypt(ByteArray(0))
        assertThrows(AEADBadTagException::class.java) { decrypt(enc.copyOf(ChunkedCrypto.HEADER_SIZE)) }
    }

    @Test
    fun appendedDataIsDetected() {
        val enc = encrypt(random(ChunkedCrypto.CHUNK, 9))
        assertThrows(AEADBadTagException::class.java) { decrypt(enc + ByteArray(40)) }
    }

    @Test
    fun streamBoundToItsContext() {
        // a stream copied over another file of the same set must not decrypt
        val enc = encrypt("file A".toByteArray(), context = "f/a.enc")
        assertArrayEquals("file A".toByteArray(), decrypt(enc, "f/a.enc"))
        assertThrows(AEADBadTagException::class.java) { decrypt(enc, "f/b.enc") }
    }

    @Test
    fun wrongPassphraseIsDetected() {
        val enc = encrypt("secret".toByteArray(Charsets.UTF_8))
        val wrongKey = ChunkedCrypto.deriveKey("wrong-passphrase".toCharArray(), salt, 10_000)
        assertThrows(AEADBadTagException::class.java) {
            ChunkedCrypto.decryptBytes(enc, wrongKey, ctx)
        }
    }

    // ---------- helpers / other entry points ----------

    @Test
    fun saltOfReadsEmbeddedSalt() {
        val enc = ChunkedCrypto.encryptToBytes("x".toByteArray(), key, salt, ctx)
        assertArrayEquals(salt, ChunkedCrypto.saltOf(enc.copyOfRange(0, 21)))
    }

    @Test
    fun decryptRangeExtractsExactSlice() {
        val data = random(ChunkedCrypto.CHUNK * 2 + 999, 11)
        val enc = encrypt(data)
        // a range crossing a chunk boundary, and a range at the very end
        for ((off, len) in listOf(100L to 5000L, (ChunkedCrypto.CHUNK - 10).toLong() to 2000L, (data.size - 99).toLong() to 99L)) {
            val out = ByteArrayOutputStream()
            ChunkedCrypto.decryptRange(ByteArrayInputStream(enc), key, ctx, off, len, out)
            assertArrayEquals(data.copyOfRange(off.toInt(), (off + len).toInt()), out.toByteArray())
        }
    }

    @Test
    fun packStyleIncrementalEncryptRoundTrip() {
        // simulate a pack: several small files concatenated through ChunkedEncryptor
        val parts = listOf(
            random(123, 21),
            ByteArray(0),
            "slack yoink".toByteArray(Charsets.UTF_8),
            random(ChunkedCrypto.CHUNK + 777, 22)
        )
        val packCtx = "f/pack-test.enc"
        val bos = ByteArrayOutputStream()
        val enc = ChunkedEncryptor(bos, key, salt, packCtx)
        val ranges = mutableListOf<Pair<Long, Int>>()
        for (part in parts) {
            ranges += enc.plainBytes to part.size
            enc.write(part, 0, part.size)
        }
        enc.close() // no size patching needed any more
        val encBytes = bos.toByteArray()
        // full decrypt equals the concatenation
        val joined = parts.fold(ByteArray(0)) { a, b -> a + b }
        assertArrayEquals(joined, ChunkedCrypto.decryptBytes(encBytes, key, packCtx))
        // and each member slices back out exactly
        for ((idx, part) in parts.withIndex()) {
            val (off, len) = ranges[idx]
            val out = ByteArrayOutputStream()
            ChunkedCrypto.decryptRange(ByteArrayInputStream(encBytes), key, packCtx, off, len.toLong(), out)
            assertArrayEquals("part $idx", part, out.toByteArray())
        }
    }

    @Test
    fun incrementalEncryptorExactChunkMultiple() {
        val data = random(ChunkedCrypto.CHUNK * 2, 23)
        val bos = ByteArrayOutputStream()
        val enc = ChunkedEncryptor(bos, key, salt, ctx)
        enc.write(data, 0, ChunkedCrypto.CHUNK)
        enc.write(data, ChunkedCrypto.CHUNK, ChunkedCrypto.CHUNK)
        enc.close()
        assertEquals(ChunkedCrypto.HEADER_SIZE + 2 * chunkCipherLen, bos.size())
        assertArrayEquals(data, decrypt(bos.toByteArray()))
    }

    @Test
    fun encryptFailsWhenSourceShrinks() {
        assertThrows(IllegalStateException::class.java) {
            ChunkedCrypto.encrypt(ByteArrayInputStream(ByteArray(10)), ByteArrayOutputStream(), key, salt, 20, ctx)
        }
    }

    @Test
    fun decryptStreamingReportsCorrectOffsets() {
        val data = random(ChunkedCrypto.CHUNK * 2 + 5, 31)
        val seen = mutableListOf<Pair<Long, Int>>()
        val total = ChunkedCrypto.decryptStreaming(ByteArrayInputStream(encrypt(data)), key, ctx) { off, _, len ->
            seen += off to len
        }
        assertEquals(data.size.toLong(), total)
        assertEquals(
            listOf(0L to ChunkedCrypto.CHUNK, ChunkedCrypto.CHUNK.toLong() to ChunkedCrypto.CHUNK, (2L * ChunkedCrypto.CHUNK) to 5),
            seen
        )
    }

    // ---------- legacy MBK1 (backups made by v1.8 and earlier) ----------

    /** Byte-for-byte the MBK1 writer of v1.8. */
    private fun legacyEncrypt(data: ByteArray): ByteArray {
        val noncePrefix = ByteArray(8).also { Random(99).nextBytes(it) }
        val out = ByteArrayOutputStream()
        out.write(
            ByteBuffer.allocate(ChunkedCrypto.HEADER_SIZE_V1)
                .put("MBK1".toByteArray()).put(1).put(salt).put(noncePrefix).putLong(data.size.toLong())
                .array()
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        var pos = 0
        var index = 0
        while (pos < data.size) {
            val len = minOf(ChunkedCrypto.CHUNK, data.size - pos)
            val nonce = ByteArray(12)
            noncePrefix.copyInto(nonce)
            ByteBuffer.wrap(nonce, 8, 4).putInt(index)
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
            out.write(cipher.doFinal(data, pos, len))
            pos += len
            index++
        }
        return out.toByteArray()
    }

    @Test
    fun legacyMbk1StillDecrypts() {
        for (data in listOf(ByteArray(0), "legacy".toByteArray(), random(ChunkedCrypto.CHUNK * 2 + 3, 50))) {
            val enc = legacyEncrypt(data)
            // the context is ignored for MBK1 (it predates AAD binding)
            assertArrayEquals(data, decrypt(enc, "f/anything.enc"))
            assertArrayEquals(salt, ChunkedCrypto.saltOf(enc.copyOfRange(0, 21)))
        }
    }

    @Test
    fun legacyMbk1TamperIsDetected() {
        val enc = legacyEncrypt(random(5000, 51))
        enc[ChunkedCrypto.HEADER_SIZE_V1 + 7] = (enc[ChunkedCrypto.HEADER_SIZE_V1 + 7] + 1).toByte()
        assertThrows(AEADBadTagException::class.java) { decrypt(enc) }
    }
}
