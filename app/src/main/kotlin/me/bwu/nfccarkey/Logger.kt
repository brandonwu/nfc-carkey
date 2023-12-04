package me.bwu.nfccarkey

import android.util.Log
import me.bwu.nfccarkey.Logger.Companion.logIfDebug

interface TestLogger<C> : Logger<C> {
    override fun info(msg: () -> String) {
        println("INFO: ${msg()}")
    }
}

class AndroidLogger<C> : Logger<C> {
    override fun info(msg: () -> String) =
        logIfDebug {
            Log.i("TAG", msg())
        }

    override fun error(msg: () -> String) =
        logIfDebug {
            Log.e("TAG", msg())
        }

    override fun debug(msg: () -> String) =
        logIfDebug {
            Log.d("TAG", msg())
        }
}

interface Logger<C> {
    fun info(msg: () -> String)
    fun error(msg: () -> String)
    fun debug(msg: () -> String)

    companion object {
        fun logIfDebug(logFun: () -> Unit) {
            if (BuildConfig.DEBUG) {
                logFun()
            }
        }
    }
}