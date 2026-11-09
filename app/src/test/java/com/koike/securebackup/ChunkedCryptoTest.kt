package com.koike.securebackup

import com.koike.securebackup.crypto.ChunkedCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Random
import javax.crypto.AEADBadTagException

class ChunkedCryptoTest {

    private val salt = ByteArray(16) { it.toByte() }
    private val key = ChunkedCrypto.deriveKey("test-passphrase".toCharArray(), salt, 10_000)

    private fun roundTrip(data: ByteArray): ByteArray {
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val decOut = ByteArrayOutputStream()
        val size = ChunkedCrypto.decrypt(ByteArrayInputStream(encOut.toByteArray()), decOut, key)
        assertEquals(data.size.toLong(), size)
        return decOut.toByteArray()
    }

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
        val data = ByteArray(ChunkedCrypto.CHUNK).also { Random(42).nextBytes(it) }
        assertArrayEquals(data, roundTrip(data))
    }

    @Test
    fun multiChunkWithRemainder() {
        val data = ByteArray(ChunkedCrypto.CHUNK * 2 + 12345).also { Random(7).nextBytes(it) }
        assertArrayEquals(data, roundTrip(data))
    }

    @Test
    fun tamperedCiphertextIsDetected() {
        val data = ByteArray(5000).also { Random(1).nextBytes(it) }
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val enc = encOut.toByteArray()
        enc[ChunkedCrypto.HEADER_SIZE + 100] = (enc[ChunkedCrypto.HEADER_SIZE + 100] + 1).toByte()
        assertThrows(AEADBadTagException::class.java) {
            ChunkedCrypto.decrypt(ByteArrayInputStream(enc), ByteArrayOutputStream(), key)
        }
    }

    @Test
    fun tamperedLaterChunkIsDetected() {
        val data = ByteArray(ChunkedCrypto.CHUNK + 5000).also { Random(3).nextBytes(it) }
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val enc = encOut.toByteArray()
        val idx = ChunkedCrypto.HEADER_SIZE + ChunkedCrypto.CHUNK + 16 + 10 // inside chunk 1
        enc[idx] = (enc[idx] + 1).toByte()
        assertThrows(AEADBadTagException::class.java) {
            ChunkedCrypto.decrypt(ByteArrayInputStream(enc), ByteArrayOutputStream(), key)
        }
    }

    @Test
    fun wrongPassphraseIsDetected() {
        val data = "secret".toByteArray(Charsets.UTF_8)
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val wrongKey = ChunkedCrypto.deriveKey("wrong-passphrase".toCharArray(), salt, 10_000)
        assertThrows(AEADBadTagException::class.java) {
            ChunkedCrypto.decrypt(ByteArrayInputStream(encOut.toByteArray()), ByteArrayOutputStream(), wrongKey)
        }
    }

    @Test
    fun saltOfReadsEmbeddedSalt() {
        val enc = ChunkedCrypto.encryptToBytes("x".toByteArray(), key, salt)
        assertArrayEquals(salt, ChunkedCrypto.saltOf(enc.copyOfRange(0, 21)))
    }

    @Test
    fun decryptRangeExtractsExactSlice() {
        val data = ByteArray(ChunkedCrypto.CHUNK * 2 + 999).also { Random(11).nextBytes(it) }
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val enc = encOut.toByteArray()
        // a range crossing a chunk boundary, and a range at the very end
        for ((off, len) in listOf(100L to 5000L, (ChunkedCrypto.CHUNK - 10).toLong() to 2000L, (data.size - 99).toLong() to 99L)) {
            val out = ByteArrayOutputStream()
            ChunkedCrypto.decryptRange(ByteArrayInputStream(enc), key, off, len, out)
            assertArrayEquals(data.copyOfRange(off.toInt(), (off + len).toInt()), out.toByteArray())
        }
    }

    @Test
    fun packStyleIncrementalEncryptRoundTrip() {
        // simulate a pack: several small files concatenated through ChunkedEncryptor
        val parts = listOf(
            ByteArray(123).also { Random(21).nextBytes(it) },
            ByteArray(0),
            "slack yoink".toByteArray(Charsets.UTF_8),
            ByteArray(ChunkedCrypto.CHUNK + 777).also { Random(22).nextBytes(it) }
        )
        val tmp = java.io.File.createTempFile("packtest", ".enc")
        try {
            val enc = com.koike.securebackup.crypto.ChunkedEncryptor(java.io.FileOutputStream(tmp), key, salt)
            val ranges = mutableListOf<Pair<Long, Int>>()
            for (part in parts) {
                ranges += enc.plainBytes to part.size
                enc.write(part, 0, part.size)
            }
            enc.close()
            java.io.RandomAccessFile(tmp, "rw").use { raf ->
                raf.seek(ChunkedCrypto.SIZE_FIELD_OFFSET.toLong())
                raf.writeLong(enc.plainBytes)
            }
            val encBytes = tmp.readBytes()
            // full decrypt equals the concatenation
            val joined = parts.fold(ByteArray(0)) { a, b -> a + b }
            assertArrayEquals(joined, ChunkedCrypto.decryptBytes(encBytes, key))
            // and each member slices back out exactly
            for ((idx, part) in parts.withIndex()) {
                val (off, len) = ranges[idx]
                val out = ByteArrayOutputStream()
                ChunkedCrypto.decryptRange(ByteArrayInputStream(encBytes), key, off, len.toLong(), out)
                assertArrayEquals("part $idx", part, out.toByteArray())
            }
        } finally {
            tmp.delete()
        }
    }

    @Test
    fun decryptStreamingReportsCorrectOffsets() {
        val data = ByteArray(ChunkedCrypto.CHUNK * 2 + 5).also { Random(31).nextBytes(it) }
        val encOut = ByteArrayOutputStream()
        ChunkedCrypto.encrypt(ByteArrayInputStream(data), encOut, key, salt, data.size.toLong())
        val seen = mutableListOf<Pair<Long, Int>>()
        val total = ChunkedCrypto.decryptStreaming(ByteArrayInputStream(encOut.toByteArray()), key) { off, _, len ->
            seen += off to len
        }
        assertEquals(data.size.toLong(), total)
        assertEquals(
            listOf(0L to ChunkedCrypto.CHUNK, ChunkedCrypto.CHUNK.toLong() to ChunkedCrypto.CHUNK, (2L * ChunkedCrypto.CHUNK) to 5),
            seen
        )
    }
}
