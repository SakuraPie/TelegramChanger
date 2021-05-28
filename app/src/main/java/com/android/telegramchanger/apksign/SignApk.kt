package com.android.telegramchanger.apksign

import com.android.telegramchanger.apksign.ApkSignerV2.SignerConfig
import com.android.telegramchanger.apksign.ApkSignerV2.sign
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OutputStream
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.encoders.Base64
import java.io.*
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.util.*
import java.util.jar.*
import java.util.regex.Pattern

/*
* Modified from from AOSP
* https://android.googlesource.com/platform/build/+/refs/tags/android-7.1.2_r39/tools/signapk/src/com/android/signapk/SignApk.java
* */
object SignApk {
    private const val CERT_SF_NAME = "META-INF/CERT.SF"
    private const val CERT_SIG_NAME = "META-INF/CERT.%s"
    private const val CERT_SF_MULTI_NAME = "META-INF/CERT%d.SF"
    private const val CERT_SIG_MULTI_NAME = "META-INF/CERT%d.%s"

    // bitmasks for which hash algorithms we need the manifest to include.
    private const val USE_SHA1 = 1
    private const val USE_SHA256 = 2

    /**
     * Digest algorithm used when signing the APK using APK Signature Scheme v2.
     */
    private const val APK_SIG_SCHEME_V2_DIGEST_ALGORITHM = "SHA-256"

    // Files matching this pattern are not copied to the output.
    private val stripPattern = Pattern.compile(
        "^(META-INF/((.*)[.](SF|RSA|DSA|EC)|com/android/otacert))|(" +
                Pattern.quote(JarFile.MANIFEST_NAME) + ")$"
    )

    /**
     * Return one of USE_SHA1 or USE_SHA256 according to the signature
     * algorithm specified in the cert.
     */
    private fun getDigestAlgorithm(cert: X509Certificate?): Int {
        val sigAlg = cert!!.sigAlgName.uppercase(Locale.US)
        return if ("SHA1WITHRSA" == sigAlg || "MD5WITHRSA" == sigAlg) {
            USE_SHA1
        } else if (sigAlg.startsWith("SHA256WITH")) {
            USE_SHA256
        } else {
            throw IllegalArgumentException(
                "unsupported signature algorithm \"" + sigAlg +
                        "\" in cert [" + cert.subjectDN
            )
        }
    }

    /**
     * Returns the expected signature algorithm for this key type.
     */
    private fun getSignatureAlgorithm(cert: X509Certificate?): String {
        val keyType = cert!!.publicKey.algorithm.uppercase(Locale.US)
        return if ("RSA".equals(keyType, ignoreCase = true)) {
            if (getDigestAlgorithm(cert) == USE_SHA256) {
                "SHA256withRSA"
            } else {
                "SHA1withRSA"
            }
        } else if ("EC".equals(keyType, ignoreCase = true)) {
            "SHA256withECDSA"
        } else {
            throw IllegalArgumentException("unsupported key type: $keyType")
        }
    }

    /**
     * Add the hash(es) of every file to the manifest, creating it if
     * necessary.
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    private fun addDigestsToManifest(jar: JarMap, hashes: Int): Manifest {
        val input = jar.getManifest()
        val output = Manifest()
        val main = output.mainAttributes
        if (input != null) {
            main.putAll(input.mainAttributes)
        } else {
            main.putValue("Manifest-Version", "1.0")
            main.putValue("Created-By", "1.0 (Android SignApk)")
        }
        var md_sha1: MessageDigest? = null
        var md_sha256: MessageDigest? = null
        if (hashes and USE_SHA1 != 0) {
            md_sha1 = MessageDigest.getInstance("SHA1")
        }
        if (hashes and USE_SHA256 != 0) {
            md_sha256 = MessageDigest.getInstance("SHA256")
        }
        val buffer = ByteArray(4096)
        var num: Int

        // We sort the input entries by name, and add them to the
        // output manifest in sorted order.  We expect that the output
        // map will be deterministic.
        val byName = TreeMap<String, JarEntry>()
        val e = jar.entries()
        while (e!!.hasMoreElements()) {
            val entry = e.nextElement()
            byName[entry.name] = entry
        }
        for (entry in byName.values) {
            val name = entry.name
            if (!entry.isDirectory && !stripPattern.matcher(name).matches()) {
                val data = jar.getInputStream(entry)
                while (data!!.read(buffer).also { num = it } > 0) {
                    md_sha1?.update(buffer, 0, num)
                    md_sha256?.update(buffer, 0, num)
                }
                var attr: Attributes? = null
                if (input != null) attr = input.getAttributes(name)
                attr = if (attr != null) Attributes(attr) else Attributes()
                // Remove any previously computed digests from this entry's attributes.
                val i = attr.keys.iterator()
                while (i.hasNext()) {
                    val key = i.next() as? Attributes.Name ?: continue
                    val attributeNameLowerCase = key.toString().lowercase(Locale.US)
                    if (attributeNameLowerCase.endsWith("-digest")) {
                        i.remove()
                    }
                }
                // Add SHA-1 digest if requested
                if (md_sha1 != null) {
                    attr.putValue(
                        "SHA1-Digest",
                        String(Base64.encode(md_sha1.digest()), StandardCharsets.US_ASCII)
                    )
                }
                // Add SHA-256 digest if requested
                if (md_sha256 != null) {
                    attr.putValue(
                        "SHA-256-Digest",
                        String(Base64.encode(md_sha256.digest()), StandardCharsets.US_ASCII)
                    )
                }
                output.entries[name] = attr
            }
        }
        return output
    }

    /**
     * Write a .SF file with a digest of the specified manifest.
     */
    @Throws(IOException::class, GeneralSecurityException::class)
    private fun writeSignatureFile(
        manifest: Manifest,
        out: OutputStream,
        hash: Int
    ) {
        val sf = Manifest()
        val main = sf.mainAttributes
        main.putValue("Signature-Version", "1.0")
        main.putValue("Created-By", "1.0 (Android SignApk)")
        // Add APK Signature Scheme v2 signature stripping protection.
        // This attribute indicates that this APK is supposed to have been signed using one or
        // more APK-specific signature schemes in addition to the standard JAR signature scheme
        // used by this code. APK signature verifier should reject the APK if it does not
        // contain a signature for the signature scheme the verifier prefers out of this set.
        main.putValue(
            ApkSignerV2.SF_ATTRIBUTE_ANDROID_APK_SIGNED_NAME,
            ApkSignerV2.SF_ATTRIBUTE_ANDROID_APK_SIGNED_VALUE
        )
        val md = MessageDigest.getInstance(if (hash == USE_SHA256) "SHA256" else "SHA1")
        val print = PrintStream(
            DigestOutputStream(ByteArrayOutputStream(), md),
            true, "UTF-8"
        )

        // Digest of the entire manifest
        manifest.write(print)
        print.flush()
        main.putValue(
            if (hash == USE_SHA256) "SHA-256-Digest-Manifest" else "SHA1-Digest-Manifest",
            String(Base64.encode(md.digest()), StandardCharsets.US_ASCII)
        )
        val entries = manifest.entries
        for ((key, value) in entries) {
            // Digest of the manifest stanza for this entry.
            print.print(
                """
    Name: $key
    
    """.trimIndent()
            )
            for ((key1, value1) in value) {
                print.print(
                    """
    $key1: $value1
    
    """.trimIndent()
                )
            }
            print.print("\r\n")
            print.flush()
            val sfAttr = Attributes()
            sfAttr.putValue(
                if (hash == USE_SHA256) "SHA-256-Digest" else "SHA1-Digest",
                String(Base64.encode(md.digest()), StandardCharsets.US_ASCII)
            )
            sf.entries[key] = sfAttr
        }
        val cout = CountOutputStream(out)
        sf.write(cout)

        // A bug in the java.util.jar implementation of Android platforms
        // up to version 1.6 will cause a spurious IOException to be thrown
        // if the length of the signature file is a multiple of 1024 bytes.
        // As a workaround, add an extra CRLF in this case.
        if (cout.size() % 1024 == 0) {
            cout.write('\r'.code)
            cout.write('\n'.code)
        }
    }

    /**
     * Sign data and write the digital signature to 'out'.
     */
    @Throws(
        IOException::class,
        CertificateEncodingException::class,
        OperatorCreationException::class,
        CMSException::class
    )
    private fun writeSignatureBlock(
        data: CMSTypedData, publicKey: X509Certificate?, privateKey: PrivateKey?, out: OutputStream
    ) {
        val certList = ArrayList<X509Certificate?>(1)
        certList.add(publicKey)
        val certs = JcaCertStore(certList)
        val gen = CMSSignedDataGenerator()
        val signer = JcaContentSignerBuilder(getSignatureAlgorithm(publicKey))
            .build(privateKey)
        gen.addSignerInfoGenerator(
            JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().build())
                .setDirectSignature(true)
                .build(signer, publicKey)
        )
        gen.addCertificates(certs)
        val sigData = gen.generate(data, false)
        ASN1InputStream(sigData.encoded).use { asn1 ->
            val dos = ASN1OutputStream.create(out, ASN1Encoding.DER)
            dos.writeObject(asn1.readObject())
        }
    }

    /**
     * Copy all the files in a manifest from input to output.  We set
     * the modification times in the output to a fixed time, so as to
     * reduce variation in the output file and make incremental OTAs
     * more efficient.
     */
    @Throws(IOException::class)
    private fun copyFiles(
        manifest: Manifest, `in`: JarMap, out: JarOutputStream,
        timestamp: Long, defaultAlignment: Int
    ) {
        val buffer = ByteArray(4096)
        var num: Int
        val entries = manifest.entries
        val names = ArrayList(entries.keys)
        Collections.sort(names)
        var firstEntry = true
        var offset = 0L

        // We do the copy in two passes -- first copying all the
        // entries that are STORED, then copying all the entries that
        // have any other compression flag (which in practice means
        // DEFLATED).  This groups all the stored entries together at
        // the start of the file and makes it easier to do alignment
        // on them (since only stored entries are aligned).
        for (name in names) {
            val inEntry = `in`.getJarEntry(name)
            var outEntry: JarEntry
            if (inEntry!!.method != JarEntry.STORED) continue
            // Preserve the STORED method of the input entry.
            outEntry = JarEntry(inEntry)
            outEntry.time = timestamp
            // Discard comment and extra fields of this entry to
            // simplify alignment logic below and for consistency with
            // how compressed entries are handled later.
            outEntry.comment = null
            outEntry.extra = null

            // 'offset' is the offset into the file at which we expect
            // the file data to begin.  This is the value we need to
            // make a multiple of 'alignement'.
            offset += (JarFile.LOCHDR + outEntry.name.length).toLong()
            if (firstEntry) {
                // The first entry in a jar file has an extra field of
                // four bytes that you can't get rid of; any extra
                // data you specify in the JarEntry is appended to
                // these forced four bytes.  This is JAR_MAGIC in
                // JarOutputStream; the bytes are 0xfeca0000.
                offset += 4
                firstEntry = false
            }
            val alignment = getStoredEntryDataAlignment(name, defaultAlignment)
            if (alignment > 0 && offset % alignment != 0L) {
                // Set the "extra data" of the entry to between 1 and
                // alignment-1 bytes, to make the file data begin at
                // an aligned offset.
                val needed = alignment - (offset % alignment).toInt()
                outEntry.extra = ByteArray(needed)
                offset += needed.toLong()
            }
            out.putNextEntry(outEntry)
            val data = `in`.getInputStream(inEntry)
            while (data!!.read(buffer).also { num = it } > 0) {
                out.write(buffer, 0, num)
                offset += num.toLong()
            }
            out.flush()
        }

        // Copy all the non-STORED entries.  We don't attempt to
        // maintain the 'offset' variable past this point; we don't do
        // alignment on these entries.
        for (name in names) {
            val inEntry = `in`.getJarEntry(name)
            var outEntry: JarEntry
            if (inEntry!!.method == JarEntry.STORED) continue
            // Create a new entry so that the compressed len is recomputed.
            outEntry = JarEntry(name)
            outEntry.time = timestamp
            out.putNextEntry(outEntry)
            val data = `in`.getInputStream(inEntry)
            while (data!!.read(buffer).also { num = it } > 0) {
                out.write(buffer, 0, num)
            }
            out.flush()
        }
    }

    /**
     * Returns the multiple (in bytes) at which the provided `STORED` entry's data must start
     * relative to start of file or `0` if alignment of this entry's data is not important.
     */
    private fun getStoredEntryDataAlignment(entryName: String, defaultAlignment: Int): Int {
        if (defaultAlignment <= 0) {
            return 0
        }
        return if (entryName.endsWith(".so")) {
            // Align .so contents to memory page boundary to enable memory-mapped
            // execution.
            4096
        } else {
            defaultAlignment
        }
    }

    @Throws(Exception::class)
    private fun signFile(
        manifest: Manifest,
        publicKey: Array<X509Certificate?>, privateKey: Array<PrivateKey?>,
        timestamp: Long, outputJar: JarOutputStream
    ) {
        // MANIFEST.MF
        var je = JarEntry(JarFile.MANIFEST_NAME)
        je.time = timestamp
        outputJar.putNextEntry(je)
        manifest.write(outputJar)
        val numKeys = publicKey.size
        for (k in 0 until numKeys) {
            // CERT.SF / CERT#.SF
            je = JarEntry(
                if (numKeys == 1) CERT_SF_NAME else String.format(
                    Locale.US,
                    CERT_SF_MULTI_NAME,
                    k
                )
            )
            je.time = timestamp
            outputJar.putNextEntry(je)
            val baos = ByteArrayOutputStream()
            writeSignatureFile(manifest, baos, getDigestAlgorithm(publicKey[k]))
            val signedData = baos.toByteArray()
            outputJar.write(signedData)

            // CERT.{EC,RSA} / CERT#.{EC,RSA}
            val keyType = publicKey[k]!!.publicKey.algorithm
            je = JarEntry(
                if (numKeys == 1) String.format(CERT_SIG_NAME, keyType) else String.format(
                    Locale.US, CERT_SIG_MULTI_NAME, k, keyType
                )
            )
            je.time = timestamp
            outputJar.putNextEntry(je)
            writeSignatureBlock(
                CMSProcessableByteArray(signedData),
                publicKey[k], privateKey[k], outputJar
            )
        }
    }

    /**
     * Converts the provided lists of private keys, their X.509 certificates, and digest algorithms
     * into a list of APK Signature Scheme v2 `SignerConfig` instances.
     */
    @Throws(InvalidKeyException::class)
    private fun createV2SignerConfigs(
        privateKeys: Array<PrivateKey?>,
        certificates: Array<X509Certificate?>,
        digestAlgorithms: Array<String>
    ): List<SignerConfig> {
        require(privateKeys.size == certificates.size) {
            ("The number of private keys must match the number of certificates: "
                    + privateKeys.size + " vs" + certificates.size)
        }
        val result: MutableList<SignerConfig> = ArrayList(privateKeys.size)
        for (i in privateKeys.indices) {
            val privateKey = privateKeys[i]
            val certificate = certificates[i]
            val publicKey = certificate!!.publicKey
            val keyAlgorithm = privateKey!!.algorithm
            if (!keyAlgorithm.equals(publicKey.algorithm, ignoreCase = true)) {
                throw InvalidKeyException(
                    "Key algorithm of private key #" + (i + 1) + " does not match key"
                            + " algorithm of public key #" + (i + 1) + ": " + keyAlgorithm
                            + " vs " + publicKey.algorithm
                )
            }
            val signerConfig = SignerConfig()
            signerConfig.privateKey = privateKey
            signerConfig.certificates = listOf<X509Certificate>(certificate)
            val signatureAlgorithms: MutableList<Int> = ArrayList(digestAlgorithms.size)
            for (digestAlgorithm in digestAlgorithms) {
                try {
                    signatureAlgorithms.add(getV2SignatureAlgorithm(keyAlgorithm, digestAlgorithm))
                } catch (e: IllegalArgumentException) {
                    throw InvalidKeyException(
                        "Unsupported key and digest algorithm combination for signer #"
                                + (i + 1), e
                    )
                }
            }
            signerConfig.signatureAlgorithms = signatureAlgorithms
            result.add(signerConfig)
        }
        return result
    }

    private fun getV2SignatureAlgorithm(keyAlgorithm: String, digestAlgorithm: String): Int {
        return if ("SHA-256".equals(digestAlgorithm, ignoreCase = true)) {
            if ("RSA".equals(keyAlgorithm, ignoreCase = true)) {
                // Use RSASSA-PKCS1-v1_5 signature scheme instead of RSASSA-PSS to guarantee
                // deterministic signatures which make life easier for OTA updates (fewer files
                // changed when deterministic signature schemes are used).
                ApkSignerV2.SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA256
            } else if ("EC".equals(keyAlgorithm, ignoreCase = true)) {
                ApkSignerV2.SIGNATURE_ECDSA_WITH_SHA256
            } else if ("DSA".equals(keyAlgorithm, ignoreCase = true)) {
                ApkSignerV2.SIGNATURE_DSA_WITH_SHA256
            } else {
                throw IllegalArgumentException("Unsupported key algorithm: $keyAlgorithm")
            }
        } else if ("SHA-512".equals(digestAlgorithm, ignoreCase = true)) {
            if ("RSA".equals(keyAlgorithm, ignoreCase = true)) {
                // Use RSASSA-PKCS1-v1_5 signature scheme instead of RSASSA-PSS to guarantee
                // deterministic signatures which make life easier for OTA updates (fewer files
                // changed when deterministic signature schemes are used).
                ApkSignerV2.SIGNATURE_RSA_PKCS1_V1_5_WITH_SHA512
            } else if ("EC".equals(keyAlgorithm, ignoreCase = true)) {
                ApkSignerV2.SIGNATURE_ECDSA_WITH_SHA512
            } else if ("DSA".equals(keyAlgorithm, ignoreCase = true)) {
                ApkSignerV2.SIGNATURE_DSA_WITH_SHA512
            } else {
                throw IllegalArgumentException("Unsupported key algorithm: $keyAlgorithm")
            }
        } else {
            throw IllegalArgumentException("Unsupported digest algorithm: $digestAlgorithm")
        }
    }

    @Throws(Exception::class)
    fun sign(
        cert: X509Certificate?, key: PrivateKey?,
        inputJar: JarMap, outputFile: FileOutputStream
    ) {
        val alignment = 4
        var hashes = 0
        val publicKey = arrayOfNulls<X509Certificate>(1)
        publicKey[0] = cert
        hashes = hashes or getDigestAlgorithm(publicKey[0])

        // Set all ZIP file timestamps to Jan 1 2009 00:00:00.
        var timestamp = 1230768000000L
        // The Java ZipEntry API we're using converts milliseconds since epoch into MS-DOS
        // timestamp using the current timezone. We thus adjust the milliseconds since epoch
        // value to end up with MS-DOS timestamp of Jan 1 2009 00:00:00.
        timestamp -= TimeZone.getDefault().getOffset(timestamp).toLong()
        val privateKey = arrayOfNulls<PrivateKey>(1)
        privateKey[0] = key

        // Generate, in memory, an APK signed using standard JAR Signature Scheme.
        val v1SignedApkBuf = ByteArrayOutputStream()
        val outputJar = JarOutputStream(v1SignedApkBuf)
        // Use maximum compression for compressed entries because the APK lives forever on
        // the system partition.
        outputJar.setLevel(9)
        val manifest = addDigestsToManifest(inputJar, hashes)
        copyFiles(manifest, inputJar, outputJar, timestamp, alignment)
        signFile(manifest, publicKey, privateKey, timestamp, outputJar)
        outputJar.close()
        val v1SignedApk = ByteBuffer.wrap(v1SignedApkBuf.toByteArray())
        v1SignedApkBuf.reset()
        val outputChunks: Array<ByteBuffer>
        val signerConfigs = createV2SignerConfigs(
            privateKey, publicKey, arrayOf(
                APK_SIG_SCHEME_V2_DIGEST_ALGORITHM
            )
        )
        outputChunks = sign(v1SignedApk, signerConfigs)

        // This assumes outputChunks are array-backed. To avoid this assumption, the
        // code could be rewritten to use FileChannel.
        for (outputChunk in outputChunks) {
            outputFile.write(
                outputChunk.array(),
                outputChunk.arrayOffset() + outputChunk.position(), outputChunk.remaining()
            )
            outputChunk.position(outputChunk.limit())
        }
    }

    /**
     * Write to another stream and track how many bytes have been
     * written.
     */
    private class CountOutputStream(out: OutputStream?) : FilterOutputStream(out) {
        private var mCount = 0
        @Throws(IOException::class)
        override fun write(b: Int) {
            super.write(b)
            mCount++
        }

        @Throws(IOException::class)
        override fun write(b: ByteArray, off: Int, len: Int) {
            super.write(b, off, len)
            mCount += len
        }

        fun size(): Int {
            return mCount
        }
    }
}