package me.bwu.nfccarkey

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import me.bwu.nfccarkey.APDULike.Companion.b
import me.bwu.nfccarkey.Util.bytesToPublicKey
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

class KeyManager(keyStoreType: String = ANDROID_KEYSTORE) {
    private val TAG = "NFCCarKeyKeyManager"
    private val KEY_ALIAS = "me.bwu.nfccarkey"

    private val keystore = KeyStore.getInstance(keyStoreType).apply { load(null) }

    fun genKeyPair(): KeyPair = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        ).run {
            initialize(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_AGREE_KEY
                ).run {
                    setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    build()
                }
            )
            generateKeyPair()
        }

    fun getOrGenEntry(): KeyPair? {
        Log.i(TAG, "Checking if a keypair already exists in the keystore")
        val key = keystore.getKey(KEY_ALIAS, null)

        return if (key == null) {
            Log.i(TAG, "Keypair does not exist, generating a fresh one")
            genKeyPair()
        } else {
            Log.i(TAG, "Keypair exists, returning the existing one")
            null
        }
    }

    /**
     * Gets the public key from the Android KeyStore if a keypair has already been generated;
     * otherwise, generate and store a new keypair and return the private key ref
     */
    fun publicKey(): ECPublicKey {
        Log.i(TAG, "Getting a public key")
        val maybeKeyPair = getOrGenEntry()
        return if (maybeKeyPair != null) {
            maybeKeyPair.public as ECPublicKey
        } else {
            keystore.getCertificate(KEY_ALIAS).publicKey as ECPublicKey
        }
    }

    /**
     * Gets the private key ref from the Android KeyStore if a keypair has already been generated;
     * otherwise, generate and store a new keypair and return the private key ref
     */
    fun privateKey(): PrivateKey {
        Log.i(TAG, "Getting a private key")
        val maybeKeyPair = getOrGenEntry()
        return if (maybeKeyPair != null) {
            maybeKeyPair.private
        } else {
            keystore.getKey(KEY_ALIAS, null) as PrivateKey
        }
    }

    fun genECDHSharedKey(otherPublicKey: ByteArray): Key {
        Log.i(TAG, "Doing ECDH")
        return KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE).run {
            init(privateKey())
            doPhase(bytesToPublicKey(otherPublicKey, publicKey().params), true)
            generateSecret("AES")
        }
    }

    companion object {
        val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

object Util {
    /**
     * Encodes the provided ECPublicKey into ANSI X9.62 uncompressed format: [0x04, X, Y]
     */
    fun publicKeyToBytes(ecPublicKey: ECPublicKey): ByteArray =
        byteArrayOf(0x04) + ecPublicKey.w.affineX.toUnsignedByteArray() + ecPublicKey.w.affineY.toUnsignedByteArray()

    /**
     * Drop the leading 0 if it exists in the byte array representation of the
     */
    fun BigInteger.toUnsignedByteArray(): ByteArray = toByteArray().run {
        if ((size > 1) and (get(0) == b(0))) {
            copyOfRange(1, size)
        } else {
            this
        }
    }

    /**
     * Decodes the provided ANSI X9.62 uncompressed EC public key into an ECPublicKey with the
     * required parameters.
     */
    fun bytesToPublicKey(publicKeyBytes: ByteArray, ecParams: ECParameterSpec): ECPublicKey {
        assert(publicKeyBytes.size == 65) // 0x04 (1-byte), X (32-byte), Y (32-byte)
        val pointSize = 32
        val x = BigInteger(publicKeyBytes.copyOfRange(1, pointSize))
        val y = BigInteger(publicKeyBytes.copyOfRange(1 + pointSize, pointSize))
        return KeyFactory.getInstance("EC").run {
            generatePublic(
                ECPublicKeySpec(
                    ECPoint(x, y), ecParams
                )
            )
        } as ECPublicKey
    }

    fun randomSalt(numBytes: Int): ByteArray =
        ByteArray(numBytes).apply { SecureRandom().nextBytes(this) }
}