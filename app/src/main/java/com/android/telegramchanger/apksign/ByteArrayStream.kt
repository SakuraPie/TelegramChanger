package com.android.telegramchanger.apksign

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

class ByteArrayStream : ByteArrayOutputStream() {
    @Synchronized
    fun readFrom(`is`: InputStream) {
        readFrom(`is`, Int.MAX_VALUE)
    }

    @Synchronized
    fun readFrom(`is`: InputStream, l: Int) {
        var len = l
        var read: Int
        val buffer = ByteArray(4096)
        try {
            while (`is`.read(buffer, 0, len.coerceAtMost(buffer.size)).also { read = it } > 0) {
                write(buffer, 0, read)
                len -= read
            }
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    val inputStream: ByteArrayInputStream
        get() = ByteArrayInputStream(buf, 0, count)
}