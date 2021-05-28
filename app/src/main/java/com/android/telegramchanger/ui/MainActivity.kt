package com.android.telegramchanger.ui

import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.util.Log
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.android.telegramchanger.R
import com.android.telegramchanger.apksign.AXML
import com.android.telegramchanger.apksign.JarMap
import com.android.telegramchanger.apksign.Keygen
import com.android.telegramchanger.apksign.SignApk
import com.android.telegramchanger.utils.ApkFile
import com.android.telegramchanger.utils.ApkFile.apkData
import com.android.telegramchanger.utils.ApkFile.apkFile
import java.io.File


@SuppressLint("ResourceType", "InflateParams")
class MainActivity : AppCompatActivity() {



    private val pkgName: EditText by lazy { findViewById(R.id.edit_package_name) }
    private val pkgLabel: EditText by lazy { findViewById(R.id.edit_apk_label) }
    private val apkFileName: TextView by lazy { findViewById(R.id.apk_file_name) }

    @SuppressLint("SetTextI18n")
    private val apkLauncher = registerForActivityResult(ActivityResultContracts.GetContent()){
        pkgName.text = null
        pkgLabel.text = null
        if (it != null){
            apkFileName.text = getString(R.string.selected)
            try {
                apkFile = ApkFile.uriToFile(this, it)
                if (apkFile != null) {
                    apkData = ApkFile.apkParser(apkFile!!, this)!!
                    pkgName.hint = apkData.first
                    pkgLabel.hint = apkData.second
                }
            } catch (e: Exception) {
                Log.w("Select Error", e)
            }
        } else {
            Toast.makeText(
                this,
                getString(R.string.generate_error_no_apk),
                Toast.LENGTH_SHORT
            )
                .show()
            Log.w("Select Error", getString(R.string.generate_error_no_apk))
        }
    }

    private val writeApkLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument()){
        if (it != null){
            if (!it.toString().endsWith(".apk")){
                Toast.makeText(this, getString(R.string.generate_error_out_file_name), Toast.LENGTH_SHORT).show()
                return@registerForActivityResult
            }
            try {
                if (apkFile != null) {
                    alertDialogBuilder.setView(R.layout.main_loading).setCancelable(false)
                    val progressDialog = alertDialogBuilder.create()
                    progressDialog.show()
                    object : Thread() {
                        @SuppressLint("SetTextI18n")
                        override fun run() {
                            patch(
                                apkFile!!,
                                it,
                                apkData.first,
                                apkData.second,
                                pkgName.text.toString(),
                                pkgLabel.text.toString()
                            )
                            progressDialog.dismiss()
                            Looper.prepare()
                            Toast.makeText(
                                this@MainActivity,
                                getString(R.string.generate_success),
                                Toast.LENGTH_LONG
                            ).show()
                            Looper.loop()
                        }
                    }.start()
                } else {
                    Toast.makeText(
                        this,
                        getString(R.string.generate_select_error),
                        Toast.LENGTH_SHORT
                    ).show()
                    Log.w("Generate Error", getString(R.string.generate_select_error))
                }
            } catch (e: Exception) {
                Toast.makeText(this, "Error: $e", Toast.LENGTH_SHORT).show()
                Log.e("Generate Error", e.toString())
            }
        }else {
            Toast.makeText(
                this,
                getString(R.string.generate_select_error),
                Toast.LENGTH_SHORT
            )
                .show()
        }
    }

    private val alertDialogBuilder by lazy { AlertDialog.Builder(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.main_select).setOnClickListener {
            apkLauncher.launch("application/vnd.android.package-archive")
        }
        findViewById<Button>(R.id.main_about).setOnClickListener {
            val intent = Intent()
            intent.setClass(this, AboutActivity::class.java)
            startActivity(intent)
        }

        findViewById<Button>(R.id.main_download).setOnClickListener {
            val intent = Intent()
            intent.setClass(this, DownloadActivity::class.java)
            startActivity(intent)
        }

        findViewById<Button>(R.id.main_generate).setOnClickListener {
            if (!checkStatus(Pair(pkgName, pkgLabel))){
                return@setOnClickListener
            }else{
                writeApkLauncher.launch("out.apk")
            }
        }

        findViewById<ImageButton>(R.id.generate_package_name).setOnClickListener {
            pkgName.setText(generatePackageName())
        }
    }

    private fun generatePackageName(): String {
        val seedFirst:List<String> = listOf("com", "org")
        val seedMid: List<String> = listOf("xuexi", "huawei", "xiaomi", "henan", "fujian",
            "cloud", "guangxi", "tencent", "baidu", "meituan")
        val seedEnd: List<String> = listOf("books", "editor", "party", "dangjian", "browser",
            "manager", "viewer", "tools", "photo", "calender", "weather")

        return "${seedFirst.random()}.${seedMid.random()}.${seedEnd.random()}"
    }

    override fun onResume() {
        super.onResume()
        if (apkFile != null){
            pkgName.hint = apkData.first
            pkgLabel.hint = apkData.second
            apkFileName.text = getString(R.string.selected)
        }
    }

    @SuppressLint("ResourceType", "InflateParams")
    private fun patch(
        apk: File,
        out: Uri, oldPkgName: String,
        oldLabel: CharSequence,
        newPkgName: String,
        newLabel: CharSequence
    ): Boolean {
        try {
            val jar = JarMap.open(apk, true)
            val je = jar.getJarEntry("AndroidManifest.xml")!!
//            val je = jar.getJarEntry("resources.arsc")
            val xml = AXML(jar.getRawData(je)!!)

            if (!xml.findAndPatch(oldPkgName to newPkgName, oldLabel.toString() to newLabel.toString())){
                return false
            }
            // Write apk changes
            jar.getOutputStream(je).write(xml.bytes)
            val keys = Keygen()
            SignApk.sign(keys.cert, keys.key, jar, contentResolver.openOutputStream(out)!!)
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
            return false
        }
        return true
    }

    private fun checkStatus(textPair: Pair<EditText, EditText>): Boolean {
        return when {
            (textPair.first.text.toString() == "" || textPair.second.text.toString() == "") && (apkFile != null) -> {
                Toast.makeText(this, getString(R.string.main_input_hint), Toast.LENGTH_SHORT).show()
                false
            }
            textPair.first.text.toString() != "" && !textPair.first.text.contains("([a-zA-Z_][a-zA-Z0-9_]*[.])*([a-zA-Z_][a-zA-Z0-9_]*)\$".toRegex()) -> {
                Toast.makeText(this, getString(R.string.main_package_name_error), Toast.LENGTH_LONG).show()
                false
            }
            apkFile == null -> {
                Toast.makeText(this, getString(R.string.generate_error_no_apk), Toast.LENGTH_SHORT).show()
                false
            }
            else -> true
        }
    }
}