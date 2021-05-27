package com.android.telegramchanger.ui

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.android.telegramchanger.R
import com.android.telegramchanger.net.DownloadUtil
import com.android.telegramchanger.utils.ApkFile
import com.github.kittinunf.fuel.Fuel
import java.io.File


class DownloadActivity: AppCompatActivity() {

    private var progressPercent: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_download)

        val downloadRadioGroup = findViewById<RadioGroup>(R.id.download_radio_group)
        val source = findViewById<TextView>(R.id.source_link)
        val progressBar = findViewById<ProgressBar>(R.id.progressBar)
        val downloadBtn = findViewById<Button>(R.id.download_download)

        val mainExecutor = ContextCompat.getMainExecutor(this)

        progressBar.visibility = View.INVISIBLE

        downloadBtn.setOnClickListener {
            progressBar.visibility = View.VISIBLE
            it.visibility = View.INVISIBLE
            val rb = findViewById<RadioButton>(downloadRadioGroup.checkedRadioButtonId)
            Toast.makeText(this, rb.text, Toast.LENGTH_SHORT).show()
            when (rb.id) {
                R.id.download_official -> {
                    object : Thread() {
                        @SuppressLint("SetTextI18n")
                        override fun run() {
                            mainExecutor.execute {
                                source.text = "${getString(R.string.source_link)} ${DownloadUtil.TG_OFFICIAL_URL}"
                            }
                            downloadApk(DownloadUtil.TG_OFFICIAL_URL, "official.apk", progressBar)
                        }
                    }.start()
                }
                R.id.download_foss -> {
                    object : Thread() {
                        @SuppressLint("SetTextI18n")
                        override fun run() {
                            val url = DownloadUtil.checkNewestUrlOnFdroid("org.telegram.messenger")
                            mainExecutor.execute { source.text = "${getString(R.string.source_link)} $url" }
                            downloadApk(url, "foss.apk", progressBar)
                        }
                    }.start()
                }
                R.id.download_nekox -> {
                    object : Thread() {
                        @SuppressLint("SetTextI18n")
                        override fun run() {
                            val url = DownloadUtil.checkNewestUrlOnFdroid("nekox.messenger")
                            mainExecutor.execute { source.text = "${getString(R.string.source_link)} $url" }
                            downloadApk(url, "nekox.apk", progressBar)
                        }
                    }.start()
            }
            }
        }
    }

    private fun downloadApk(url: String, name: String, progressBar: ProgressBar) {
        Fuel.download(url).fileDestination { _, _ ->
            File(externalCacheDir, name)
        }.progress { readBytes, totalBytes ->
            val progress = readBytes.toFloat() / totalBytes.toFloat()
            progressPercent = (progress * 100).toInt()
            progressBar.progress = progressPercent
        }.response { _, _, result ->
            ApkFile.apkFile = File(externalCacheDir.toString() + "/" + name)
            if (File(externalCacheDir.toString() + "/" + name).exists()) {
                Log.d("log", "download completed ")
                Toast.makeText(this, getString(R.string.download_complete), Toast.LENGTH_SHORT)
                    .show()
                ApkFile.apkData = ApkFile.apkParser(ApkFile.apkFile!!, null)!!
                Log.d("log", externalCacheDir.toString() + "/" + name)
                finish()
            }else{
                Toast.makeText(this, result.toString().split('\n')[0].replace("[", ""), Toast.LENGTH_LONG)
                    .show()
            }
        }.timeout(15000)
    }

}