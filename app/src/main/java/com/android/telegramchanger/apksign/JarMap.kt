package com.android.telegramchanger.apksign

import java.io.*
import java.util.*
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarInputStream
import java.util.jar.Manifest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

abstract class JarMap : Closeable {
    var entryMap: LinkedHashMap<String, JarEntry>? = null
//    open val file: File?
//        get() = null
    open fun getFile(): File? = null

    abstract fun getManifest(): Manifest?
//    abstract val manifest: Manifest?
    @Throws(IOException::class)
    open fun getInputStream(ze: ZipEntry): InputStream? {
        val e = getMapEntry(ze.name)
        return e?.data?.inputStream
    }

    fun getOutputStream(ze: ZipEntry): OutputStream {
        if (entryMap == null) entryMap = LinkedHashMap()
        val e = JarMapEntry(ze.name)
        entryMap!![ze.name] = e
        return e.data
    }

    @Throws(IOException::class)
    open fun getRawData(ze: ZipEntry): ByteArray? {
        val e = getMapEntry(ze.name)
        return e?.data?.toByteArray()
    }

    abstract fun entries(): Enumeration<JarEntry>?
    fun getEntry(name: String): ZipEntry? {
        return getJarEntry(name)
    }

    open fun getJarEntry(name: String): JarEntry? {
        return getMapEntry(name)
    }

    fun getMapEntry(name: String): JarMapEntry? {
        var e: JarMapEntry? = null
        if (entryMap != null) e = entryMap!![name] as JarMapEntry?
        return e
    }

    private class FileMap(file: File?, verify: Boolean, mode: Int) : JarMap() {
        private val jarFile: JarFile = JarFile(file, verify, mode)
        override fun getFile(): File {
            return File(jarFile.name)
        }

        @Throws(IOException::class)
        override fun getManifest(): Manifest? {
            return jarFile.manifest
        }

        @Throws(IOException::class)
        override fun getInputStream(ze: ZipEntry): InputStream? {
            val `is` = super.getInputStream(ze)
            return `is` ?: jarFile.getInputStream(ze)
        }

        @Throws(IOException::class)
        override fun getRawData(ze: ZipEntry): ByteArray? {
            val b = super.getRawData(ze)
            if (b != null) return b
            val bytes = ByteArrayStream()
            bytes.readFrom(jarFile.getInputStream(ze))
            return bytes.toByteArray()
        }

        override fun entries(): Enumeration<JarEntry>? {
            return jarFile.entries()
        }

        override fun getJarEntry(name: String): JarEntry? {
            val e: JarEntry? = getMapEntry(name)
            return e ?: jarFile.getJarEntry(name)
        }

        @Throws(IOException::class)
        override fun close() {
            jarFile.close()
        }

    }

    private class StreamMap(`is`: InputStream?, verify: Boolean) : JarMap() {
        private val jis: JarInputStream = JarInputStream(`is`, verify)
        override fun getManifest(): Manifest? {
            return jis.manifest
        }

        override fun entries(): Enumeration<JarEntry>? {
            return Collections.enumeration(entryMap!!.values)
        }

        @Throws(IOException::class)
        override fun close() {
            jis.close()
        }

        init {
            entryMap = LinkedHashMap()
            var entry: JarEntry
            while (jis.nextJarEntry.also { entry = it } != null) {
                entryMap!![entry.name] = JarMapEntry(entry, jis)
            }
        }
    }

    class JarMapEntry : JarEntry {
        var data: ByteArrayStream

        internal constructor(je: JarEntry?, `is`: InputStream?) : super(je) {
            data = ByteArrayStream()
            data.readFrom(`is`!!)
        }

        internal constructor(s: String?) : super(s) {
            data = ByteArrayStream()
        }
    }

    companion object {
        @Throws(IOException::class)
        fun open(file: File?, verify: Boolean): JarMap {
            return FileMap(file, verify, ZipFile.OPEN_READ)
        }

        @Throws(IOException::class)
        fun open(`is`: InputStream?, verify: Boolean): JarMap {
            return StreamMap(`is`, verify)
        }
    }
}