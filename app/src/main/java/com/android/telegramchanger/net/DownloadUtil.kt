package com.android.telegramchanger.net

import org.jsoup.Jsoup

object DownloadUtil {

    const val TG_OFFICIAL_URL = "https://telegram.org/dl/android/apk"
    private const val FDROID_URL_HEAD = "https://f-droid.org/"

    fun checkNewestUrlOnFdroid (pkgName: String):String {
        var downloadUrl = ""
                val url = "${FDROID_URL_HEAD}packages/$pkgName"
                val doc = Jsoup.connect(url).get()
                if (doc.title().toString().contains("F-Droid", true)) {
                    val versionCode = doc.select("div.package-version-header:nth-child(2) > a:nth-child(2)").attr("name")
                    downloadUrl = parseDownloadUrlFromVersion(versionCode, pkgName)
                }
        return downloadUrl
    }

    private fun parseDownloadUrlFromVersion(versionCode: String, pkgName: String):String {
        return "${FDROID_URL_HEAD}repo/${pkgName}_${versionCode}.apk"
    }
}