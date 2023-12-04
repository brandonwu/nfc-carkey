package me.bwu.nfccarkey

import me.bwu.nfccarkey.APDULike.Companion.b
import me.bwu.nfccarkey.APDULike.Companion.enumMap

enum class APDUClass(override val content: Byte) : APDULike {
    GENERAL(0),
    PROPRIETARY(b(0x80)),
    ;

    override fun toString(): String = hexToString()

    companion object {
        private val byteToEnum = enumMap(values(), APDUClass::content)
        fun fromCat(cat: Byte) : APDUClass? = byteToEnum[cat]
    }
}

enum class GeneralAPDU(override val inst: Byte) : APDU {
    SELECT_AID(b(0xa4)),
    ;

    override fun toString(): String = hexToString()

    companion object {
        private val byteToEnum = enumMap(values(), GeneralAPDU::content)
        fun fromInst(inst: Byte) : GeneralAPDU? = byteToEnum[inst]
    }
}

enum class ProprietaryAPDU(override val inst: Byte) : APDU {
    GET_PUBLIC_KEY(b(0x04)),
    GET_AUTH_RESPONSE(b(0x11)),
    GET_CARD_INFO(b(0x14)),
    ;

    override fun toString(): String = hexToString()


    companion object {
        private val byteToEnum = enumMap(values(), ProprietaryAPDU::inst)
        fun fromInst(inst: Byte) : ProprietaryAPDU? = byteToEnum[inst]
    }
}

data class UnknownAPDU(val payload: ByteArray) : APDU {
    override val inst: Byte = payload[1]
    override val name: String = UnknownAPDU::class.simpleName !! // Not used.
}

sealed interface APDU : APDULike {
    val inst: Byte
    override val content: Byte
        get() = inst

    companion object {
        fun fromPayload(payload: ByteArray) : APDU =
            when (APDUClass.fromCat(payload[0])) {
                APDUClass.GENERAL -> GeneralAPDU.fromInst(payload[1])
                APDUClass.PROPRIETARY -> ProprietaryAPDU.fromInst(payload[1])
                null -> null
            } ?: UnknownAPDU(payload)
    }
}

sealed interface APDULike {
    val name: String
    val content: Byte
    fun hexToString() = "%s(%02x)".format(name, content)

    companion object {
        /**
         * When ints are auto-downcast when provided as a byte param, they are treated as signed
         * values and can exceed the signed byte range
         */
        fun b(int: Int): Byte = int.toByte()

        // Gets the mapping of contents to instance for the enums
        fun <T : APDULike> enumMap(values: Array<T>, contents: T.() -> Byte): Map<Byte, T> =
            values.associateBy(contents)
    }
}