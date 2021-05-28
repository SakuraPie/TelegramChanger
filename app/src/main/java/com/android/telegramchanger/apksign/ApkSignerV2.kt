package com.android.telegramchanger.apksign

import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.security.spec.*
import java.util.*

/**
 * APK Signature Scheme v2 signer.
 *
 *
 * APK Signature Scheme v2 is a whole-file signature scheme which aims to protect every single
 * bit of the APK, as opposed to the JAR Signature Scheme which protects only the names and
 * uncompressed contents of ZIP entries.
 */
object ApkSignerV2 {
    /*
     * The two main goals of APK Signature Scheme v2 are:
     * 1. Detect any unauthorized modifications to the APK. This is achieved by making the signature
     *    cover every byte of the APK being signed.
     * 2. Enable much faster signature and integrity verification. This is achieved by requiring
     *    only a minimal amount of APK parsing before the signature is verified, thus completely
     *    bypassing ZIP entry decompression and by making integrity verification parallelizable by
     *    employing a hash tree.
     *
     * The generated signature block is wrapped into an APK Signing Block and inserted into the
     * original APK immediately before the start of ZIP Central Directory. This is to ensure that
     * JAR and ZIP parsers continue to work on the signed APK. The APK Signing Block is designed for
     * extensibility. For example, a future signature scheme could insert its signatures there as
     * well. The contract of the APK Signing Block is that all contents outside of the block must be
     * protected by signatures inside the block.
     */
    private const val SIGNATURE_RSA_PSS_WITH_SHA256 = 0x0101
    private const val SIGNATURE_RSA_PSS_WITH_SHA512 = 0x0102
    const val SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103
    const val SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 = 0x0104
    const val SIGNATURE_ECDSA_WITH_SHA256 = 0x0201
    const val SIGNATURE_ECDSA_WITH_SHA512 = 0x0202
    const val SIGNATURE_DSA_WITH_SHA256 = 0x0301
    const val SIGNATURE_DSA_WITH_SHA512 = 0x0302

    /**
     * `.SF` file header section attribute indicating that the APK is signed not just with
     * JAR signature scheme but also with APK Signature Scheme v2 or newer. This attribute
     * facilitates v2 signature stripping detection.
     *
     *
     * The attribute contains a comma-separated set of signature scheme IDs.
     */
    const val SF_ATTRIBUTE_ANDROID_APK_SIGNED_NAME = "X-Android-APK-Signed"
    const val SF_ATTRIBUTE_ANDROID_APK_SIGNED_VALUE = "2"
    private const val CONTENT_DIGEST_CHUNKED_SHA256 = 0
    private const val CONTENT_DIGEST_CHUNKED_SHA512 = 1
    private const val CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES = 1024 * 1024
    private val APK_SIGNING_BLOCK_MAGIC = byteArrayOf(
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
    )
    private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a

    /**
     * Signs the provided APK using APK Signature Scheme v2 and returns the signed APK as a list of
     * consecutive chunks.
     *
     *
     * NOTE: To enable APK signature verifier to detect v2 signature stripping, header sections
     * of META-INF/ *.SF files of APK being signed must contain the
     * `X-Android-APK-Signed: true` attribute.
     *
     * @param iApk contents of the APK to be signed. The APK starts at the current position
     * of the buffer and ends at the limit of the buffer.
     * @param signerConfigs signer configurations, one for each signer.
     *
     * @throws ApkParseException if the APK cannot be parsed.
     * @throws InvalidKeyException if a signing key is not suitable for this signature scheme or
     * cannot be used in general.
     * @throws SignatureException if an error occurs when computing digests of generating
     * signatures.
     */
    @JvmStatic
    @Throws(ApkParseException::class, InvalidKeyException::class, SignatureException::class)
    fun sign(
        iApk: ByteBuffer,
        signerConfigs: List<SignerConfig>
    ): Array<ByteBuffer> {
        // Slice/create a view in the inputApk to make sure that:
        // 1. inputApk is what's between position and limit of the original inputApk, and
        // 2. changes to position, limit, and byte order are not reflected in the original.
        var inputApk = iApk
        val originalInputApk = inputApk
        inputApk = originalInputApk.slice()
        inputApk.order(ByteOrder.LITTLE_ENDIAN)

        // Locate ZIP End of Central Directory (EoCD), Central Directory, and check that Central
        // Directory is immediately followed by the ZIP End of Central Directory.
        val eocdOffset = ZipUtils.findZipEndOfCentralDirectoryRecord(inputApk)
        if (eocdOffset == -1) {
            throw ApkParseException("Failed to locate ZIP End of Central Directory")
        }
        if (ZipUtils.isZip64EndOfCentralDirectoryLocatorPresent(inputApk, eocdOffset)) {
            throw ApkParseException("ZIP64 format not supported")
        }
        inputApk.position(eocdOffset)
        val centralDirSizeLong = ZipUtils.getZipEocdCentralDirectorySizeBytes(inputApk)
        if (centralDirSizeLong > Int.MAX_VALUE) {
            throw ApkParseException(
                "ZIP Central Directory size out of range: $centralDirSizeLong"
            )
        }
        val centralDirSize = centralDirSizeLong.toInt()
        val centralDirOffsetLong = ZipUtils.getZipEocdCentralDirectoryOffset(inputApk)
        if (centralDirOffsetLong > Int.MAX_VALUE) {
            throw ApkParseException(
                "ZIP Central Directory offset in file out of range: $centralDirOffsetLong"
            )
        }
        var centralDirOffset = centralDirOffsetLong.toInt()
        val expectedEocdOffset = centralDirOffset + centralDirSize
        if (expectedEocdOffset < centralDirOffset) {
            throw ApkParseException(
                "ZIP Central Directory extent too large. Offset: " + centralDirOffset
                        + ", size: " + centralDirSize
            )
        }
        if (eocdOffset != expectedEocdOffset) {
            throw ApkParseException(
                "ZIP Central Directory not immeiately followed by ZIP End of"
                        + " Central Directory. CD end: " + expectedEocdOffset
                        + ", EoCD start: " + eocdOffset
            )
        }

        // Create ByteBuffers holding the contents of everything before ZIP Central Directory,
        // ZIP Central Directory, and ZIP End of Central Directory.
        inputApk.clear()
        val beforeCentralDir = getByteBuffer(inputApk, centralDirOffset)
        val centralDir = getByteBuffer(inputApk, eocdOffset - centralDirOffset)
        // Create a copy of End of Central Directory because we'll need modify its contents later.
        val eocdBytes = ByteArray(inputApk.remaining())
        inputApk[eocdBytes]
        val eocd = ByteBuffer.wrap(eocdBytes)
        eocd.order(inputApk.order())

        // Figure which which digests to use for APK contents.
        val contentDigestAlgorithms: MutableSet<Int> = HashSet()
        for (signerConfig in signerConfigs) {
            for (signatureAlgorithm in signerConfig.signatureAlgorithms!!) {
                contentDigestAlgorithms.add(
                    getSignatureAlgorithmContentDigestAlgorithm(signatureAlgorithm)
                )
            }
        }

        // Compute digests of APK contents.
        val contentDigests: Map<Int, ByteArray> = try {
            computeContentDigests(
                contentDigestAlgorithms, arrayOf(beforeCentralDir, centralDir, eocd)
            )
        } catch (e: DigestException) {
            throw SignatureException("Failed to compute digests of APK", e)
        } // digest algorithm ID -> digest

        // Sign the digests and wrap the signatures and signer info into an APK Signing Block.
        val apkSigningBlock =
            ByteBuffer.wrap(generateApkSigningBlock(signerConfigs, contentDigests))

        // Update Central Directory Offset in End of Central Directory Record. Central Directory
        // follows the APK Signing Block and thus is shifted by the size of the APK Signing Block.
        centralDirOffset += apkSigningBlock.remaining()
        eocd.clear()
        ZipUtils.setZipEocdCentralDirectoryOffset(eocd, centralDirOffset.toLong())

        // Follow the Java NIO pattern for ByteBuffer whose contents have been consumed.
        originalInputApk.position(originalInputApk.limit())

        // Reset positions (to 0) and limits (to capacity) in the ByteBuffers below to follow the
        // Java NIO pattern for ByteBuffers which are ready for their contents to be read by caller.
        // Contrary to the name, this does not clear the contents of these ByteBuffer.
        beforeCentralDir.clear()
        centralDir.clear()
        eocd.clear()

        // Insert APK Signing Block immediately before the ZIP Central Directory.
        return arrayOf(
            beforeCentralDir,
            apkSigningBlock,
            centralDir,
            eocd
        )
    }

    @Throws(DigestException::class)
    private fun computeContentDigests(
        digestAlgorithms: Set<Int>,
        contents: Array<ByteBuffer>
    ): Map<Int, ByteArray> {
        // For each digest algorithm the result is computed as follows:
        // 1. Each segment of contents is split into consecutive chunks of 1 MB in size.
        //    The final chunk will be shorter iff the length of segment is not a multiple of 1 MB.
        //    No chunks are produced for empty (zero length) segments.
        // 2. The digest of each chunk is computed over the concatenation of byte 0xa5, the chunk's
        //    length in bytes (uint32 little-endian) and the chunk's contents.
        // 3. The output digest is computed over the concatenation of the byte 0x5a, the number of
        //    chunks (uint32 little-endian) and the concatenation of digests of chunks of all
        //    segments in-order.
        var chunkCount = 0
        for (input in contents) {
            chunkCount += getChunkCount(input.remaining())
        }
        val digestsOfChunks: MutableMap<Int, ByteArray> = HashMap(digestAlgorithms.size)
        for (digestAlgorithm in digestAlgorithms) {
            val digestOutputSizeBytes = getContentDigestAlgorithmOutputSizeBytes(digestAlgorithm)
            val concatenationOfChunkCountAndChunkDigests =
                ByteArray(5 + chunkCount * digestOutputSizeBytes)
            concatenationOfChunkCountAndChunkDigests[0] = 0x5a
            setUnsignedInt32LittleEngian(
                chunkCount, concatenationOfChunkCountAndChunkDigests
            )
            digestsOfChunks[digestAlgorithm] = concatenationOfChunkCountAndChunkDigests
        }
        var chunkIndex = 0
        val chunkContentPrefix = ByteArray(5)
        chunkContentPrefix[0] = 0xa5.toByte()
        // Optimization opportunity: digests of chunks can be computed in parallel.
        for (input in contents) {
            while (input.hasRemaining()) {
                val chunkSize =
                    input.remaining().coerceAtMost(CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES)
                val chunk = getByteBuffer(input, chunkSize)
                for (digestAlgorithm in digestAlgorithms) {
                    val jcaAlgorithmName =
                        getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm)
                    val md: MessageDigest = try {
                        MessageDigest.getInstance(jcaAlgorithmName)
                    } catch (e: NoSuchAlgorithmException) {
                        throw DigestException(
                            "$jcaAlgorithmName MessageDigest not supported", e
                        )
                    }
                    // Reset position to 0 and limit to capacity. Position would've been modified
                    // by the preceding iteration of this loop. NOTE: Contrary to the method name,
                    // this does not modify the contents of the chunk.
                    chunk.clear()
                    setUnsignedInt32LittleEngian(chunk.remaining(), chunkContentPrefix)
                    md.update(chunkContentPrefix)
                    md.update(chunk)
                    val concatenationOfChunkCountAndChunkDigests = digestsOfChunks[digestAlgorithm]
                    val expectedDigestSizeBytes =
                        getContentDigestAlgorithmOutputSizeBytes(digestAlgorithm)
                    assert(concatenationOfChunkCountAndChunkDigests != null)
                    val actualDigestSizeBytes = md.digest(
                        concatenationOfChunkCountAndChunkDigests!!,
                        5 + chunkIndex * expectedDigestSizeBytes,
                        expectedDigestSizeBytes
                    )
                    if (actualDigestSizeBytes != expectedDigestSizeBytes) {
                        throw DigestException(
                            "Unexpected output size of " + md.algorithm
                                    + " digest: " + actualDigestSizeBytes
                        )
                    }
                }
                chunkIndex++
            }
        }
        val result: MutableMap<Int, ByteArray> = HashMap(digestAlgorithms.size)
        for ((digestAlgorithm, concatenationOfChunkCountAndChunkDigests) in digestsOfChunks) {
            val jcaAlgorithmName = getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm)
            val md: MessageDigest = try {
                MessageDigest.getInstance(jcaAlgorithmName)
            } catch (e: NoSuchAlgorithmException) {
                throw DigestException("$jcaAlgorithmName MessageDigest not supported", e)
            }
            result[digestAlgorithm] = md.digest(concatenationOfChunkCountAndChunkDigests)
        }
        return result
    }

    private fun getChunkCount(inputSize: Int): Int {
        return (inputSize + CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES - 1) / CONTENT_DIGESTED_CHUNK_MAX_SIZE_BYTES
    }

    private fun setUnsignedInt32LittleEngian(value: Int, result: ByteArray) {
        result[1] = (value and 0xff).toByte()
        result[1 + 1] = (value shr 8 and 0xff).toByte()
        result[1 + 2] = (value shr 16 and 0xff).toByte()
        result[1 + 3] = (value shr 24 and 0xff).toByte()
    }

    @Throws(InvalidKeyException::class, SignatureException::class)
    private fun generateApkSigningBlock(
        signerConfigs: List<SignerConfig>,
        contentDigests: Map<Int, ByteArray>
    ): ByteArray {
        val apkSignatureSchemeV2Block =
            generateApkSignatureSchemeV2Block(signerConfigs, contentDigests)
        return generateApkSigningBlock(apkSignatureSchemeV2Block)
    }

    private fun generateApkSigningBlock(apkSignatureSchemeV2Block: ByteArray): ByteArray {
        // FORMAT:
        // uint64:  size (excluding this field)
        // repeated ID-value pairs:
        //     uint64:           size (excluding this field)
        //     uint32:           ID
        //     (size - 4) bytes: value
        // uint64:  size (same as the one above)
        // uint128: magic
        val resultSize = (8 // size
                + 8 + 4 + apkSignatureSchemeV2Block.size // v2Block as ID-value pair
                + 8 // size
                + 16) // magic
        val result = ByteBuffer.allocate(resultSize)
        result.order(ByteOrder.LITTLE_ENDIAN)
        val blockSizeFieldValue = (resultSize - 8).toLong()
        result.putLong(blockSizeFieldValue)
        val pairSizeFieldValue = (4 + apkSignatureSchemeV2Block.size).toLong()
        result.putLong(pairSizeFieldValue)
        result.putInt(APK_SIGNATURE_SCHEME_V2_BLOCK_ID)
        result.put(apkSignatureSchemeV2Block)
        result.putLong(blockSizeFieldValue)
        result.put(APK_SIGNING_BLOCK_MAGIC)
        return result.array()
    }

    @Throws(InvalidKeyException::class, SignatureException::class)
    private fun generateApkSignatureSchemeV2Block(
        signerConfigs: List<SignerConfig>,
        contentDigests: Map<Int, ByteArray>
    ): ByteArray {
        // FORMAT:
        // * length-prefixed sequence of length-prefixed signer blocks.
        val signerBlocks: MutableList<ByteArray> = ArrayList(signerConfigs.size)
        var signerNumber = 0
        for (signerConfig in signerConfigs) {
            signerNumber++
            val signerBlock: ByteArray = try {
                generateSignerBlock(signerConfig, contentDigests)
            } catch (e: InvalidKeyException) {
                throw InvalidKeyException("Signer #$signerNumber failed", e)
            } catch (e: SignatureException) {
                throw SignatureException("Signer #$signerNumber failed", e)
            }
            signerBlocks.add(signerBlock)
        }
        return encodeAsSequenceOfLengthPrefixedElements(
            arrayOf(
                encodeAsSequenceOfLengthPrefixedElements(signerBlocks)
            )
        )
    }

    @Throws(InvalidKeyException::class, SignatureException::class)
    private fun generateSignerBlock(
        signerConfig: SignerConfig,
        contentDigests: Map<Int, ByteArray>
    ): ByteArray {
        if (signerConfig.certificates!!.isEmpty()) {
            throw SignatureException("No certificates configured for signer")
        }
        val publicKey = signerConfig.certificates!![0].publicKey
        val encodedPublicKey = encodePublicKey(publicKey)
        val signedData = V2SignatureSchemeBlock.SignedData()
        try {
            signedData.certificates = encodeCertificates(signerConfig.certificates)
        } catch (e: CertificateEncodingException) {
            throw SignatureException("Failed to encode certificates", e)
        }
        val digests: MutableList<Pair<Int, ByteArray>> = ArrayList(
            signerConfig.signatureAlgorithms!!.size
        )
        for (signatureAlgorithm in signerConfig.signatureAlgorithms!!) {
            val contentDigestAlgorithm =
                getSignatureAlgorithmContentDigestAlgorithm(signatureAlgorithm)
            val contentDigest = contentDigests[contentDigestAlgorithm]
                ?: throw RuntimeException(
                    getContentDigestAlgorithmJcaDigestAlgorithm(contentDigestAlgorithm)
                            + " content digest for "
                            + getSignatureAlgorithmJcaSignatureAlgorithm(signatureAlgorithm)
                            + " not computed"
                )
            digests.add(Pair.create(signatureAlgorithm, contentDigest))
        }
        signedData.digests = digests
        val signer = V2SignatureSchemeBlock.Signer()
        // FORMAT:
        // * length-prefixed sequence of length-prefixed digests:
        //   * uint32: signature algorithm ID
        //   * length-prefixed bytes: digest of contents
        // * length-prefixed sequence of certificates:
        //   * length-prefixed bytes: X.509 certificate (ASN.1 DER encoded).
        // * length-prefixed sequence of length-prefixed additional attributes:
        //   * uint32: ID
        //   * (length - 4) bytes: value
        signer.signedData = encodeAsSequenceOfLengthPrefixedElements(
            arrayOf(
                encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(signedData.digests),
                encodeAsSequenceOfLengthPrefixedElements(signedData.certificates), ByteArray(0)
            )
        )
        signer.publicKey = encodedPublicKey
        signer.signatures = ArrayList()
        for (signatureAlgorithm in signerConfig.signatureAlgorithms!!) {
            val signatureParams = getSignatureAlgorithmJcaSignatureAlgorithm(signatureAlgorithm)
            val jcaSignatureAlgorithm = signatureParams.first!!
            val jcaSignatureAlgorithmParams = signatureParams.second
            val signatureBytes: ByteArray = try {
                val signature = Signature.getInstance(jcaSignatureAlgorithm)
                signature.initSign(signerConfig.privateKey)
                if (jcaSignatureAlgorithmParams != null) {
                    signature.setParameter(jcaSignatureAlgorithmParams)
                }
                signature.update(signer.signedData)
                signature.sign()
            } catch (e: InvalidKeyException) {
                throw InvalidKeyException("Failed sign using $jcaSignatureAlgorithm", e)
            } catch (e: NoSuchAlgorithmException) {
                throw SignatureException("Failed sign using $jcaSignatureAlgorithm", e)
            } catch (e: InvalidAlgorithmParameterException) {
                throw SignatureException("Failed sign using $jcaSignatureAlgorithm", e)
            } catch (e: SignatureException) {
                throw SignatureException("Failed sign using $jcaSignatureAlgorithm", e)
            }
            try {
                val signature = Signature.getInstance(jcaSignatureAlgorithm)
                signature.initVerify(publicKey)
                if (jcaSignatureAlgorithmParams != null) {
                    signature.setParameter(jcaSignatureAlgorithmParams)
                }
                signature.update(signer.signedData)
                if (!signature.verify(signatureBytes)) {
                    throw SignatureException("Signature did not verify")
                }
            } catch (e: InvalidKeyException) {
                throw InvalidKeyException(
                    "Failed to verify generated " + jcaSignatureAlgorithm
                            + " signature using public key from certificate", e
                )
            } catch (e: NoSuchAlgorithmException) {
                throw SignatureException(
                    "Failed to verify generated " + jcaSignatureAlgorithm
                            + " signature using public key from certificate", e
                )
            } catch (e: InvalidAlgorithmParameterException) {
                throw SignatureException(
                    "Failed to verify generated " + jcaSignatureAlgorithm
                            + " signature using public key from certificate", e
                )
            } catch (e: SignatureException) {
                throw SignatureException(
                    "Failed to verify generated " + jcaSignatureAlgorithm
                            + " signature using public key from certificate", e
                )
            }
            (signer.signatures as ArrayList<Pair<Int, ByteArray>>).add(Pair.create(signatureAlgorithm, signatureBytes))
        }

        // FORMAT:
        // * length-prefixed signed data
        // * length-prefixed sequence of length-prefixed signatures:
        //   * uint32: signature algorithm ID
        //   * length-prefixed bytes: signature of signed data
        // * length-prefixed bytes: public key (X.509 SubjectPublicKeyInfo, ASN.1 DER encoded)
        return encodeAsSequenceOfLengthPrefixedElements(
            arrayOf(
                signer.signedData!!,
                encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
                    signer.signatures!!
                ),
                signer.publicKey!!
            )
        )
    }

    @Throws(InvalidKeyException::class)
    private fun encodePublicKey(publicKey: PublicKey): ByteArray {
        var encodedPublicKey: ByteArray? = null
        if ("X.509" == publicKey.format) {
            encodedPublicKey = publicKey.encoded
        }
        if (encodedPublicKey == null) {
            encodedPublicKey = try {
                KeyFactory.getInstance(publicKey.algorithm)
                    .getKeySpec(publicKey, X509EncodedKeySpec::class.java)
                    .encoded
            } catch (e: NoSuchAlgorithmException) {
                throw InvalidKeyException(
                    "Failed to obtain X.509 encoded form of public key " + publicKey
                            + " of class " + publicKey.javaClass.name,
                    e
                )
            } catch (e: InvalidKeySpecException) {
                throw InvalidKeyException(
                    "Failed to obtain X.509 encoded form of public key " + publicKey
                            + " of class " + publicKey.javaClass.name,
                    e
                )
            }
        }
        if (encodedPublicKey == null || encodedPublicKey.isEmpty()) {
            throw InvalidKeyException(
                "Failed to obtain X.509 encoded form of public key " + publicKey
                        + " of class " + publicKey.javaClass.name
            )
        }
        return encodedPublicKey
    }

    @Throws(CertificateEncodingException::class)
    fun encodeCertificates(certificates: List<X509Certificate>?): List<ByteArray> {
        val result: MutableList<ByteArray> = ArrayList()
        for (certificate in certificates!!) {
            result.add(certificate.encoded)
        }
        return result
    }

    private fun encodeAsSequenceOfLengthPrefixedElements(sequence: List<ByteArray>?): ByteArray {
        return encodeAsSequenceOfLengthPrefixedElements(
            sequence!!.toTypedArray()
        )
    }

    private fun encodeAsSequenceOfLengthPrefixedElements(sequence: Array<ByteArray>): ByteArray {
        var payloadSize = 0
        for (element in sequence) {
            payloadSize += 4 + element.size
        }
        val result = ByteBuffer.allocate(payloadSize)
        result.order(ByteOrder.LITTLE_ENDIAN)
        for (element in sequence) {
            result.putInt(element.size)
            result.put(element)
        }
        return result.array()
    }

    private fun encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes(
        sequence: List<Pair<Int, ByteArray>>?
    ): ByteArray {
        var resultSize = 0
        for (element in sequence!!) {
            resultSize += 12 + element.second!!.size
        }
        val result = ByteBuffer.allocate(resultSize)
        result.order(ByteOrder.LITTLE_ENDIAN)
        for (element in sequence) {
            val second = element.second!!
            result.putInt(8 + second.size)
            result.putInt(element.first!!)
            result.putInt(second.size)
            result.put(second)
        }
        return result.array()
    }

    /**
     * Relative *get* method for reading `size` number of bytes from the current
     * position of this buffer.
     *
     *
     * This method reads the next `size` bytes at this buffer's current position,
     * returning them as a `ByteBuffer` with start set to 0, limit and capacity set to
     * `size`, byte order set to this buffer's byte order; and then increments the position by
     * `size`.
     */
    private fun getByteBuffer(source: ByteBuffer, size: Int): ByteBuffer {
        require(size >= 0) { "size: $size" }
        val originalLimit = source.limit()
        val position = source.position()
        val limit = position + size
        if (limit < position || limit > originalLimit) {
            throw BufferUnderflowException()
        }
        source.limit(limit)
        return try {
            val result = source.slice()
            result.order(source.order())
            source.position(limit)
            result
        } finally {
            source.limit(originalLimit)
        }
    }

    private fun getSignatureAlgorithmJcaSignatureAlgorithm(sigAlgorithm: Int): Pair<String, out AlgorithmParameterSpec?> {
        return when (sigAlgorithm) {
            SIGNATURE_RSA_PSS_WITH_SHA256 -> Pair.create<String, PSSParameterSpec?>(
                "SHA256withRSA/PSS",
                PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1
                )
            )
            SIGNATURE_RSA_PSS_WITH_SHA512 -> Pair.create<String, PSSParameterSpec?>(
                "SHA512withRSA/PSS",
                PSSParameterSpec(
                    "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1
                )
            )
            SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA256withRSA",
                null
            )
            SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA512withRSA",
                null
            )
            SIGNATURE_ECDSA_WITH_SHA256 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA256withECDSA",
                null
            )
            SIGNATURE_ECDSA_WITH_SHA512 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA512withECDSA",
                null
            )
            SIGNATURE_DSA_WITH_SHA256 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA256withDSA",
                null
            )
            SIGNATURE_DSA_WITH_SHA512 -> Pair.create<String, AlgorithmParameterSpec?>(
                "SHA512withDSA",
                null
            )
            else -> throw IllegalArgumentException(
                "Unknown signature algorithm: 0x"
                        + java.lang.Long.toHexString(sigAlgorithm.toLong())
            )
        }
    }

    private fun getSignatureAlgorithmContentDigestAlgorithm(sigAlgorithm: Int): Int {
        return when (sigAlgorithm) {
            SIGNATURE_RSA_PSS_WITH_SHA256, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256, SIGNATURE_ECDSA_WITH_SHA256, SIGNATURE_DSA_WITH_SHA256 -> CONTENT_DIGEST_CHUNKED_SHA256
            SIGNATURE_RSA_PSS_WITH_SHA512, SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512, SIGNATURE_ECDSA_WITH_SHA512, SIGNATURE_DSA_WITH_SHA512 -> CONTENT_DIGEST_CHUNKED_SHA512
            else -> throw IllegalArgumentException(
                "Unknown signature algorithm: 0x"
                        + java.lang.Long.toHexString(sigAlgorithm.toLong())
            )
        }
    }

    private fun getContentDigestAlgorithmJcaDigestAlgorithm(digestAlgorithm: Int): String {
        return when (digestAlgorithm) {
            CONTENT_DIGEST_CHUNKED_SHA256 -> "SHA-256"
            CONTENT_DIGEST_CHUNKED_SHA512 -> "SHA-512"
            else -> throw IllegalArgumentException(
                "Unknown content digest algorthm: $digestAlgorithm"
            )
        }
    }

    private fun getContentDigestAlgorithmOutputSizeBytes(digestAlgorithm: Int): Int {
        return when (digestAlgorithm) {
            CONTENT_DIGEST_CHUNKED_SHA256 -> 256 / 8
            CONTENT_DIGEST_CHUNKED_SHA512 -> 512 / 8
            else -> throw IllegalArgumentException(
                "Unknown content digest algorthm: $digestAlgorithm"
            )
        }
    }

    /**
     * Signer configuration.
     */
    class SignerConfig {
        /** Private key.  */
        @JvmField
        var privateKey: PrivateKey? = null

        /**
         * Certificates, with the first certificate containing the public key corresponding to
         * [.privateKey].
         */
        @JvmField
        var certificates: List<X509Certificate>? = null

        /**
         * List of signature algorithms with which to sign (see `SIGNATURE_...` constants).
         */
        @JvmField
        var signatureAlgorithms: List<Int>? = null
    }

    private class V2SignatureSchemeBlock {
        class Signer {
            var signedData: ByteArray? = null
            var signatures: MutableList<Pair<Int, ByteArray>>? = null
            var publicKey: ByteArray? = null
        }

        class SignedData {
            var digests: List<Pair<Int, ByteArray>>? = null
            var certificates: List<ByteArray>? = null
        }
    }

    /**
     * Indicates that APK file could not be parsed.
     */
    class ApkParseException(message: String?) : Exception(message) {

        companion object {
            private const val serialVersionUID = 1L
        }
    }

    /**
     * Pair of two elements.
     */
    private class Pair<A, B> private constructor(first: A, second: B) {
        val first: A?
        val second: B?
        override fun hashCode(): Int {
            val prime = 31
            var result = 1
            result = prime * result + (first?.hashCode() ?: 0)
            result = prime * result + (second?.hashCode() ?: 0)
            return result
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) {
                return true
            }
            if (other == null) {
                return false
            }
            if (javaClass != other.javaClass) {
                return false
            }
            other as Pair<*, *>
            if (first == null) {
                if (other.first != null) {
                    return false
                }
            } else if (first != other.first) {
                return false
            }
            return if (second == null) {
                other.second == null
            } else second == other.second
        }

        companion object {
            fun <A, B> create(first: A, second: B): Pair<A, B> {
                return Pair(first, second)
            }
        }

        init {
            this.first = first
            this.second = second
        }
    }
}