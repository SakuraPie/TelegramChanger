package com.android.telegramchanger.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Looper
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.RequestPermission
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
import com.android.telegramchanger.utils.Permission
import java.io.File
import java.io.FileOutputStream


@SuppressLint("ResourceType", "InflateParams")
class MainActivity : AppCompatActivity() {



    val pkgName: EditText by lazy { findViewById(R.id.edit_package_name) }
    private val pkgLabel: EditText by lazy { findViewById(R.id.edit_apk_label) }

    private val apkLauncher = registerForActivityResult(ActivityResultContracts.GetContent()){
        pkgName.text = null
        pkgLabel.text = null
        if (it != null){
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

    private val alertDialogBuilder by lazy { AlertDialog.Builder(this) }

    private val requestPermissionLauncher =
        registerForActivityResult(RequestPermission()
        ) { isGranted: Boolean ->
            Permission.readPermission = isGranted
        }


    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        if (Permission.canRead(this)) {
            Log.d("READ_PERMISSION", "READ_PERMISSION GET!")
            Permission.readPermission = true
        } else {
            requestPermissionLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
        }


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
            if (checkText(Pair(pkgName, pkgLabel))){
                try {
                    if (apkFile != null) {
                        alertDialogBuilder.setView(R.layout.main_loading).setCancelable(false)
                        val progressDialog = alertDialogBuilder.create()
                        progressDialog.show()
                        val out = File(externalCacheDir, "out.apk")
                        object : Thread() {
                            @SuppressLint("SetTextI18n")
                            override fun run() {
                                patch(
                                    apkFile!!,
                                    out,
                                    apkData.first,
                                    apkData.second,
                                    pkgName.text.toString(),
                                    pkgLabel.text.toString()
                                )
                                progressDialog.dismiss()
                                Looper.prepare()
                                Toast.makeText(this@MainActivity, getString(R.string.generate_success), Toast.LENGTH_LONG).show()
                                Looper.loop()
                            }
                        }.start()
                    } else {
                        Toast.makeText(
                            this,
                            getString(R.string.generate_error_no_apk),
                            Toast.LENGTH_SHORT
                        ).show()
                        Log.w("Generate Error", getString(R.string.generate_error_no_apk))
                    }
                } catch (e: Exception) {
                    Toast.makeText(this, "Error: $e", Toast.LENGTH_SHORT).show()
                    Log.e("Generate Error", e.toString())
                }
            }else{
                return@setOnClickListener
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (apkFile != null){
            pkgName.hint = apkData.first
            pkgLabel.hint = apkData.second
        }
    }

    @SuppressLint("ResourceType", "InflateParams")
    private fun patch(
        apk: File,
        out: File, oldPkgName: String,
        oldLabel: CharSequence,
        newPkgName: String,
        newLabel: CharSequence
    ): Boolean {
        try {
            val jar = JarMap.open(apk, true)
            val je = jar.getJarEntry("AndroidManifest.xml")
//            val je = jar.getJarEntry("resources.arsc")
            val xml = AXML(jar.getRawData(je))

            if (!xml.findAndPatch(oldPkgName to newPkgName, oldLabel.toString() to newLabel.toString())){
                return false
            }
            // Write apk changes
            jar.getOutputStream(je).write(xml.bytes)
            val keys = Keygen()
            SignApk.sign(keys.cert, keys.key, jar, FileOutputStream(out))
        } catch (e: Exception) {
            e.printStackTrace()
            Toast.makeText(this, e.toString(), Toast.LENGTH_LONG).show()
            return false
        }
        return true
    }

    private fun checkText(textPair: Pair<EditText, EditText>): Boolean {
        return when {
            textPair.first.text.toString() == "" || textPair.second.text.toString() == "" -> {
                Toast.makeText(this, getString(R.string.main_input_hint), Toast.LENGTH_SHORT).show()
                false
            }
            textPair.first.text.toString() != "" && !textPair.first.text.contains("([a-zA-Z_][a-zA-Z0-9_]*[.])*([a-zA-Z_][a-zA-Z0-9_]*)\$".toRegex()) -> {
                Toast.makeText(this, getString(R.string.main_package_name_error), Toast.LENGTH_LONG).show()
                false
            }
            else -> true
        }
    }
}