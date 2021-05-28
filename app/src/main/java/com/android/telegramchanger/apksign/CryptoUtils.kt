package com.android.telegramchanger.apksign

import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

object CryptoUtils {
    private var ID_TO_ALG: MutableMap<String, String>? = null
    private var ALG_TO_ID: MutableMap<String, String>? = null
    @Throws(Exception::class)
    fun getSignatureAlgorithm(key: Key): String {
        return when (key.algorithm) {
            "EC" -> {
                val curveSize: Int
                val factory = KeyFactory.getInstance("EC")
                curveSize = when (key) {
                    is PublicKey -> {
                        val spec = factory.getKeySpec(
                            key,
                            ECPublicKeySpec::class.java
                        )
                        spec.params.curve.field.fieldSize
                    }
                    is PrivateKey -> {
                        val spec = factory.getKeySpec(
                            key,
                            ECPrivateKeySpec::class.java
                        )
                        spec.params.curve.field.fieldSize
                    }
                    else -> {
                        throw InvalidKeySpecException()
                    }
                }
                when {
                    curveSize <= 256 -> {
                        "SHA256withECDSA"
                    }
                    curveSize <= 384 -> {
                        "SHA384withECDSA"
                    }
                    else -> {
                        "SHA512withECDSA"
                    }
                }
            }
            "RSA" -> {
                "SHA256withRSA"
            }
            else -> {
                throw IllegalArgumentException("Unsupported key type " + key.algorithm)
            }
        }
    }

    @Throws(Exception::class)
    fun getSignatureAlgorithmIdentifier(key: Key): AlgorithmIdentifier {
        val id = ALG_TO_ID!![getSignatureAlgorithm(key)]
            ?: throw IllegalArgumentException("Unsupported key type " + key.algorithm)
        return AlgorithmIdentifier(ASN1ObjectIdentifier(id))
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    fun readCertificate(input: InputStream): X509Certificate {
        return input.use { ipt ->
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ipt) as X509Certificate
        }
    }

    /** Read a PKCS#8 format private key.  */
    @Throws(IOException::class, GeneralSecurityException::class)
    fun readPrivateKey(input: InputStream): PrivateKey {
        return input.use { ipt ->
            val buf = ByteArrayStream()
            buf.readFrom(ipt)
            val bytes = buf.toByteArray()
            /* Check to see if this is in an EncryptedPrivateKeyInfo structure. */
            val spec = PKCS8EncodedKeySpec(bytes)
            /*
                 * Now it's in a PKCS#8 PrivateKeyInfo structure. Read its Algorithm
                 * OID and use that to construct a KeyFactory.
                 */
            val bIn = ASN1InputStream(ByteArrayInputStream(spec.encoded))
            val pki = PrivateKeyInfo.getInstance(bIn.readObject())
            val algOid = pki.privateKeyAlgorithm.algorithm.id
            KeyFactory.getInstance(algOid).generatePrivate(spec)
        }
    }

    init {
        ID_TO_ALG = HashMap()
        ALG_TO_ID = HashMap()
        (ID_TO_ALG as HashMap<String, String>)[X9ObjectIdentifiers.ecdsa_with_SHA256.id] = "SHA256withECDSA"
        (ID_TO_ALG as HashMap<String, String>)[X9ObjectIdentifiers.ecdsa_with_SHA384.id] = "SHA384withECDSA"
        (ID_TO_ALG as HashMap<String, String>)[X9ObjectIdentifiers.ecdsa_with_SHA512.id] = "SHA512withECDSA"
        (ID_TO_ALG as HashMap<String, String>)[PKCSObjectIdentifiers.sha1WithRSAEncryption.id] = "SHA1withRSA"
        (ID_TO_ALG as HashMap<String, String>)[PKCSObjectIdentifiers.sha256WithRSAEncryption.id] = "SHA256withRSA"
        (ID_TO_ALG as HashMap<String, String>)[PKCSObjectIdentifiers.sha512WithRSAEncryption.id] = "SHA512withRSA"
        (ALG_TO_ID as HashMap<String, String>)["SHA256withECDSA"] = X9ObjectIdentifiers.ecdsa_with_SHA256.id
        (ALG_TO_ID as HashMap<String, String>)["SHA384withECDSA"] = X9ObjectIdentifiers.ecdsa_with_SHA384.id
        (ALG_TO_ID as HashMap<String, String>)["SHA512withECDSA"] = X9ObjectIdentifiers.ecdsa_with_SHA512.id
        (ALG_TO_ID as HashMap<String, String>)["SHA1withRSA"] = PKCSObjectIdentifiers.sha1WithRSAEncryption.id
        (ALG_TO_ID as HashMap<String, String>)["SHA256withRSA"] = PKCSObjectIdentifiers.sha256WithRSAEncryption.id
        (ALG_TO_ID as HashMap<String, String>)["SHA512withRSA"] = PKCSObjectIdentifiers.sha512WithRSAEncryption.id
    }
}