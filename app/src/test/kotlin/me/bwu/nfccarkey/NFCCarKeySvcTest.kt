package me.bwu.nfccarkey

import me.bwu.nfccarkey.NFCCarKeySvc.Companion.byteArrayOfInts
import org.junit.Assert.*
import org.junit.Test

internal class NFCCarKeySvcTest {

    private val carKeySvc = NFCCarKeySvc("JKS")

    @Test
    fun `Handle known input payload and return a response`() {
    }

    @Test
    fun `Handle unknown input payload and return null`() {

    }

    @Test
    fun `Public key request should be the correct size`() {
        val resp = carKeySvc.cardPublicKeyResponse()

        resp.size shouldEqual 1 /*0x04 for uncompressed ANSI X9.62 key*/ + 64 /*for X, Y*/ + 2 /*Success trailer*/
    }

    @Test
    fun `Respond to a challenge-response auth request`() {

    }

    @Test
    fun `Respond to a card information request`() {
        val resp = carKeySvc.cardInfoResponse()

        resp.size shouldEqual 4
        resp shouldEqual byteArrayOfInts(0, 0x01, 0x90, 0x00)
    }

    @Test
    fun `Return a successful trailer of length 2`() {
        val resp = carKeySvc.successResponse()

        resp.size shouldEqual 2
    }

    companion object {
        inline infix fun <reified T> T.shouldEqual(other: T) {
            assertEquals(this, other)
        }

        infix fun ByteArray.shouldEqual(other: ByteArray) {
            assertArrayEquals(this, other)
        }
    }
}