package com.superpay.merchant

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.*
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : Activity() {
    private val baseUrl = "https://swappaykassma.vercel.app"
    private val prefs by lazy { getSharedPreferences("paykassma_session", MODE_PRIVATE) }
    private lateinit var userId: EditText
    private lateinit var password: EditText
    private lateinit var source: Spinner
    private lateinit var status: TextView
    private val packages = listOf(
        "Google Pay" to "com.google.android.apps.nbu.paisa.user",
        "PhonePe" to "com.phonepe.app",
        "BharatPe" to "com.bharatpe.app",
        "Paytm Business" to "com.paytm.business"
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 28, 24, 24)
        }
        root.addView(TextView(this).apply { text = "Paykassma Merchant"; textSize = 24f })
        root.addView(TextView(this).apply {
            text = "Sign in with your Paykassma Merchant account. Choose only one payment app to monitor."
            textSize = 14f
        })
        userId = EditText(this).apply { hint = "Merchant User ID"; singleLine = true }
        password = EditText(this).apply {
            hint = "Password"
            inputType = 129
            singleLine = true
        }
        root.addView(userId)
        root.addView(password)
        root.addView(Button(this).apply {
            text = "Merchant Login"
            setOnClickListener { login() }
        })
        root.addView(TextView(this).apply { text = "Payment app to monitor"; textSize = 16f })
        source = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, packages.map { it.first })
        }
        root.addView(source)
        root.addView(Button(this).apply {
            text = "Save selected payment app"
            setOnClickListener { configureSource() }
        })
        root.addView(Button(this).apply {
            text = "Enable Notification Access"
            setOnClickListener { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) }
        })
        root.addView(Button(this).apply {
            text = "Open Paykassma Dashboard"
            setOnClickListener { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("$baseUrl/login.html"))) }
        })
        status = TextView(this).apply { textSize = 14f; setPadding(0, 18, 0, 0) }
        root.addView(status)
        setContentView(ScrollView(this).apply { addView(root) })
        if (prefs.getString("token", null) != null) {
            userId.setText(prefs.getString("user_id", ""))
            status.text = "Merchant session saved. Select the payment app and save it."
        }
    }

    private fun login() {
        val id = userId.text.toString().trim()
        val pass = password.text.toString()
        if (id.isBlank() || pass.isBlank()) {
            status.text = "Enter your Merchant User ID and password."
            return
        }
        status.text = "Signing in…"
        Thread {
            try {
                val response = request("/api/login", JSONObject()
                    .put("user_id", id)
                    .put("password", pass)
                    .put("login_type", "standard"))
                val user = response.optJSONObject("user")
                if (!response.optBoolean("ok") || user == null) throw Exception(response.optString("message", "Login failed"))
                if (user.optString("role") != "MERCHANT") throw Exception("This app accepts Merchant accounts only.")
                prefs.edit()
                    .putString("token", response.getString("token"))
                    .putString("user_id", user.optString("user_id", id))
                    .apply()
                runOnUiThread {
                    password.text.clear()
                    status.text = "Merchant login successful. Now save one payment app."
                }
            } catch (e: Exception) {
                runOnUiThread { status.text = e.message ?: "Login failed." }
            }
        }.start()
    }

    private fun configureSource() {
        val token = prefs.getString("token", null)
        if (token.isNullOrBlank()) {
            status.text = "Please sign in first."
            return
        }
        val selected = packages[source.selectedItemPosition].second
        status.text = "Saving selected payment app…"
        Thread {
            try {
                val response = request("/api/device-events", JSONObject()
                    .put("action", "configure_source")
                    .put("source_package", selected), token)
                if (!response.optBoolean("ok")) throw Exception(response.optString("message", "Could not save source"))
                prefs.edit().putString("source_package", selected).apply()
                runOnUiThread { status.text = "Saved. Enable Paykassma notification access in Android Settings." }
            } catch (e: Exception) {
                runOnUiThread { status.text = e.message ?: "Could not save payment app." }
            }
        }.start()
    }

    private fun request(path: String, body: JSONObject, token: String? = null): JSONObject {
        val connection = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15000
            readTimeout = 15000
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            if (!token.isNullOrBlank()) setRequestProperty("Authorization", "Bearer $token")
        }
        try {
            connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
            val text = stream.bufferedReader().use { it.readText() }
            return JSONObject(text)
        } finally {
            connection.disconnect()
        }
    }
}