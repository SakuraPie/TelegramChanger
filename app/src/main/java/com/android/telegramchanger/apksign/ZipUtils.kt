package com.android.telegramchanger.apksign

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.and

/**
 * Assorted ZIP format helpers.
 *
 *
 * NOTE: Most helper methods operating on `ByteBuffer` instances expect that the byte
 * order of these buffers is little-endian.
 */
object ZipUtils {
    private const val ZIP_EOCD_REC_MIN_SIZE = 22
    private const val ZIP_EOCD_REC_SIG = 0x06054b50
    private const val ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
    private const val ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
    private const val ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20
    private const val ZIP64_EOCD_LOCATOR_SIZE = 20
    private const val ZIP64_EOCD_LOCATOR_SIG = 0x07064b50
    private const val UINT16_MAX_VALUE = 0xffff

    /**
     * Returns the position at which ZIP End of Central Directory record starts in the provided
     * buffer or `-1` if the record is not present.
     *
     *
     * NOTE: Byte order of `zipContents` must be little-endian.
     */
    fun findZipEndOfCentralDirectoryRecord(zipContents: ByteBuffer): Int {
        assertByteOrderLittleEndian(zipContents)

        // ZIP End of Central Directory (EOCD) record is located at the very end of the ZIP archive.
        // The record can be identified by its 4-byte signature/magic which is located at the very
        // beginning of the record. A complication is that the record is variable-length because of
        // the comment field.
        // The algorithm for locating the ZIP EOCD record is as follows. We search backwards from
        // end of the buffer for the EOCD record signature. Whenever we find a signature, we check
        // the candidate record's comment length is such that the remainder of the record takes up
        // exactly the remaining bytes in the buffer. The search is bounded because the maximum
        // size of the comment field is 65535 bytes because the field is an unsigned 16-bit number.
        val archiveSize = zipContents.capacity()
        if (archiveSize < ZIP_EOCD_REC_MIN_SIZE) {
            return -1
        }
        val maxCommentLength = (archiveSize - ZIP_EOCD_REC_MIN_SIZE).coerceAtMost(UINT16_MAX_VALUE)
        val eocdWithEmptyCommentStartPosition = archiveSize - ZIP_EOCD_REC_MIN_SIZE
        for (expectedCommentLength in 0 until maxCommentLength) {
            val eocdStartPos = eocdWithEmptyCommentStartPosition - expectedCommentLength
            if (zipContents.getInt(eocdStartPos) == ZIP_EOCD_REC_SIG) {
                val actualCommentLength = getUnsignedInt16(
                    zipContents,
                    eocdStartPos + ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET
                )
                if (actualCommentLength == expectedCommentLength) {
                    return eocdStartPos
                }
            }
        }
        return -1
    }

    /**
     * Returns `true` if the provided buffer contains a ZIP64 End of Central Directory
     * Locator.
     *
     *
     * NOTE: Byte order of `zipContents` must be little-endian.
     */
    fun isZip64EndOfCentralDirectoryLocatorPresent(
        zipContents: ByteBuffer,
        zipEndOfCentralDirectoryPosition: Int
    ): Boolean {
        assertByteOrderLittleEndian(zipContents)

        // ZIP64 End of Central Directory Locator immediately precedes the ZIP End of Central
        // Directory Record.
        val locatorPosition = zipEndOfCentralDirectoryPosition - ZIP64_EOCD_LOCATOR_SIZE
        return if (locatorPosition < 0) {
            false
        } else zipContents.getInt(locatorPosition) == ZIP64_EOCD_LOCATOR_SIG
    }

    /**
     * Returns the offset of the start of the ZIP Central Directory in the archive.
     *
     *
     * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
     */
    fun getZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer): Long {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory)
        return getUnsignedInt32(
            zipEndOfCentralDirectory,
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET
        )
    }

    /**
     * Sets the offset of the start of the ZIP Central Directory in the archive.
     *
     *
     * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
     */
    fun setZipEocdCentralDirectoryOffset(zipEndOfCentralDirectory: ByteBuffer, offset: Long) {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory)
        setUnsignedInt32(
            zipEndOfCentralDirectory,
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET,
            offset
        )
    }

    /**
     * Returns the size (in bytes) of the ZIP Central Directory.
     *
     *
     * NOTE: Byte order of `zipEndOfCentralDirectory` must be little-endian.
     */
    fun getZipEocdCentralDirectorySizeBytes(zipEndOfCentralDirectory: ByteBuffer): Long {
        assertByteOrderLittleEndian(zipEndOfCentralDirectory)
        return getUnsignedInt32(
            zipEndOfCentralDirectory,
            zipEndOfCentralDirectory.position() + ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET
        )
    }

    private fun assertByteOrderLittleEndian(buffer: ByteBuffer) {
        require(buffer.order() == ByteOrder.LITTLE_ENDIAN) { "ByteBuffer byte order must be little endian" }
    }

    private fun getUnsignedInt16(buffer: ByteBuffer, offset: Int): Int {
        return (buffer.getShort(offset) and 0xffff.toShort()).toInt()
    }

    private fun getUnsignedInt32(buffer: ByteBuffer, offset: Int): Long {
        return (buffer.getInt(offset) and 0xffffffffL.toInt()).toLong()
    }

    private fun setUnsignedInt32(buffer: ByteBuffer, offset: Int, value: Long) {
        require(!(value < 0 || value > 0xffffffffL)) { "uint32 value of out range: $value" }
        buffer.putInt(buffer.position() + offset, value.toInt())
    }
}