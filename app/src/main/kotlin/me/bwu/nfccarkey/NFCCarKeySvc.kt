package me.bwu.nfccarkey

import android.annotation.SuppressLint
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import me.bwu.nfccarkey.Util.publicKeyToBytes
import me.bwu.nfccarkey.Util.randomSalt
import java.util.*
import javax.crypto.Cipher

class NFCCarKeySvc(keyStoreType: String = KeyManager.ANDROID_KEYSTORE) : HostApduService() {
    private val TAG = "NFCCarKeySvc"
    private val keymgr = KeyManager(keyStoreType)

    override fun processCommandApdu(payload: ByteArray?, extras: Bundle?): ByteArray? {
        if (payload == null) {
            throw NullPointerException("APDU payload was null. This shouldn't happen.")
        }

        val apdu = APDU.fromPayload(payload)
        Log.i(TAG, "Received APDU $apdu")
        Log.d(TAG, "Received payload ${payload.toHex()}")

        // Map each APDU to its handler.
        val response = when (apdu) {
            GeneralAPDU.SELECT_AID -> successResponse()
            ProprietaryAPDU.GET_PUBLIC_KEY -> cardPublicKeyResponse()
            ProprietaryAPDU.GET_AUTH_RESPONSE -> authChallengeResponse(payload)
            ProprietaryAPDU.GET_CARD_INFO -> cardInfoResponse()
            is UnknownAPDU -> null
        }

        if (response != null) {
            Log.d(TAG, "Responding with ${response.size} bytes response: ${response.toHex()}")
        } else {
            Log.d(TAG, "This APDU is unhandled, not sending a response")
        }

        return response
    }

    override fun onDeactivated(reason: Int) {
        Log.d(TAG, "Deactivating service due to ${
            when(reason) {
                DEACTIVATION_LINK_LOSS -> "the phone moving away from the reader"
                DEACTIVATION_DESELECTED -> "a different AID being selected"
                else -> "an unknown reason with ID $reason"
            }
        }")
    }

    fun cardPublicKeyResponse(): ByteArray {
        Log.i(TAG, "Processing card public key request")
        val publicKey = keymgr.publicKey()
        Log.d(TAG, "Got public key: $publicKey")

        return publicKeyToBytes(publicKey) + successResponse()
    }

    @SuppressLint("GetInstance")
    fun authChallengeResponse(payload: ByteArray): ByteArray {
        Log.i(TAG, "Processing challenge-response auth")
        val PUBLIC_KEY_OFFSET = 5
        val CHALLENGE_OFFSET = PUBLIC_KEY_OFFSET + 65
        val CHALLENGE_END = CHALLENGE_OFFSET + 16

        val carPublicKey = payload.copyOfRange(PUBLIC_KEY_OFFSET, CHALLENGE_OFFSET)
        Log.d(TAG, "ANSI X9.62 encoded car public key: ${carPublicKey.toHex()}")

        val challenge = payload.copyOfRange(CHALLENGE_OFFSET, CHALLENGE_END)
        Log.d(TAG, "Challenge value: ${challenge.toHex()}")

        // TODO maybe need to skip generating salt for an all 0 challenge (when pairing)
        // Overwrite the first 4 bytes of the challenge with a random salt per protocol
        val saltedChallenge = randomSalt(4).copyInto(challenge)
        Log.d(TAG, "Salted challenge value: ${saltedChallenge.toHex()}")

        val ecSharedKey = keymgr.genECDHSharedKey(carPublicKey)
        Log.d(TAG, "ECDH shared key: $ecSharedKey")

        return Cipher.getInstance("AES_128/ECB/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, ecSharedKey)
            doFinal(saltedChallenge)
        } + successResponse()
    }

    // Returns the response of a card key
    fun cardInfoResponse(): ByteArray {
        Log.i(TAG, "Processing card info response")
        return byteArrayOfInts(0x00, 0x01) + successResponse()
    }

    fun successResponse(): ByteArray {
        Log.i(TAG, "Returning success response")
        return byteArrayOfInts(0x90, 0x00)
    }

    companion object {
        fun byteArrayOfInts(vararg els: Int): ByteArray = els.map { it.toByte() }.toByteArray()
        fun ByteArray.toHex() = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
    }
}