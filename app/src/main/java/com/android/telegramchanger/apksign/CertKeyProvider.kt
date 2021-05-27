package com.android.telegramchanger.apksign

import java.security.PrivateKey
import java.security.cert.X509Certificate

interface CertKeyProvider {
    val cert: X509Certificate
    val key: PrivateKey
}