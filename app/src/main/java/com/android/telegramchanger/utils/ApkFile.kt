package com.android.telegramchanger.utils

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.webkit.MimeTypeMap
import android.widget.Toast
import net.dongliu.apk.parser.bean.ApkMeta
import java.io.*
import kotlin.random.Random


object ApkFile {

    var apkFile: File? = null
    lateinit var apkData: Pair<String, String>

    @Throws(IOException::class)
    fun copy(source: InputStream, target: OutputStream) {
        val buf = ByteArray(8192)
        var length: Int
        while (source.read(buf).also { length = it } > 0) {
            target.write(buf, 0, length)
        }
    }

    fun uriToFile(context: Context, uri: Uri): File? =
        if (uri.scheme == ContentResolver.SCHEME_FILE)
            File(requireNotNull(uri.path))
        else if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            val contentResolver = context.contentResolver
            val displayName = "${System.currentTimeMillis()}${Random.nextInt(0, 9999)}.${
                MimeTypeMap.getSingleton()
                    .getExtensionFromMimeType(contentResolver.getType(uri))
            }"
            val ios = contentResolver.openInputStream(uri)
            if (ios != null) {
                File("${context.cacheDir.absolutePath}/$displayName")
                    .apply {
                        val fos = FileOutputStream(this)
                        copy(ios, fos)
                        fos.close()
                        ios.close()
                    }
            } else null
        } else null

    fun apkParser(apk: File, context: Context?): Pair<String, String>? {
        return try {
            val apkFile = net.dongliu.apk.parser.ApkFile(apk)
            val apkMeta: ApkMeta = apkFile.apkMeta
            Pair(apkMeta.packageName, apkMeta.label)
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
            if (context != null) Toast.makeText(context, e.toString(), Toast.LENGTH_LONG).show()
            apkFile = null
            null
        }
    }


}