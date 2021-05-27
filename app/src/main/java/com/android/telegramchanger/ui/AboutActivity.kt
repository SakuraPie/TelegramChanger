package com.android.telegramchanger.ui

import android.annotation.SuppressLint
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.android.telegramchanger.R


class AboutActivity: AppCompatActivity() {
    @SuppressLint("SetTextI18n")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_about)
        findViewById<TextView>(R.id.about_version).text = "${findViewById<TextView>(R.id.about_version).text}${getVersionName()}"
    }

    @Throws(Exception::class)
    fun getVersionName(): String? {
        return packageManager.getPackageInfo(packageName, 0).versionName
    }
}