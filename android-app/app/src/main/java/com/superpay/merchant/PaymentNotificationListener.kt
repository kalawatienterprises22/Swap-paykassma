package com.superpay.merchant

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.util.UUID
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class PaymentNotificationListener : NotificationListenerService() {
    private val baseUrl = "https://swappaykassma.vercel.app"
    private val allowed = setOf(
        "com.google.android.apps.nbu.paisa.user",
        "com.phonepe.app",
        "com.bharatpe.app",
        "com.paytm.business"
    )
    private val paymentSignal = Regex("(?i)(credited|received|debited|paid|payment|transfer|transaction|upi|deposit|withdraw|refund|₹|\\bINR\\b|\\bRs\\.?\\b)")
    private val sensitiveSignal = Regex("(?i)(\\bOTP\\b|one.time.password|password|\\bPIN\\b|verification code|login code)")
    private val heartbeatHandler = Handler(Looper.getMainLooper())
    private val heartbeatTask = object : Runnable {
        override fun run() {
            val prefs = getSharedPreferences("paykassma_session", MODE_PRIVATE)
            val token = prefs.getString("token", null)
            if (token != null) sendHeartbeat(token, prefs)
            heartbeatHandler.postDelayed(this, 60_000)
        }
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        heartbeatHandler.removeCallbacks(heartbeatTask)
        heartbeatHandler.post(heartbeatTask)
    }

    override fun onListenerDisconnected() {
        heartbeatHandler.removeCallbacks(heartbeatTask)
        super.onListenerDisconnected()
    }

    private fun sendHeartbeat(token: String, prefs: android.content.SharedPreferences) {
        val deviceId = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_id", it).apply()
        }
        Thread {
            val connection = (URL("$baseUrl/api/device-events").openConnection() as HttpURLConnection)
            try {
                connection.requestMethod = "POST"
                connection.connectTimeout = 10000
                connection.readTimeout = 10000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Authorization", "Bearer $token")
                val payload = JSONObject()
                    .put("action", "heartbeat")
                    .put("device_id", deviceId)
                    .put("device_model", "${Build.MANUFACTURER} ${Build.MODEL}".take(120))
                    .put("app_version", "1.0.0")
                connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                connection.inputStream?.close()
            } catch (_: Exception) {
                // Device presence expires automatically if the server cannot be reached.
            } finally {
                connection.disconnect()
            }
        }.start()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val prefs = getSharedPreferences("paykassma_session", MODE_PRIVATE)
        val token = prefs.getString("token", null) ?: return
        val selectedPackage = prefs.getString("source_package", null)
        sendHeartbeat(token, prefs)
        if (selectedPackage.isNullOrBlank()) return
        if (sbn.packageName != selectedPackage || sbn.packageName !in allowed) return

        val extras = sbn.notification.extras
        val title = extras.getCharSequence("android.title")?.toString()?.take(200).orEmpty()
        val text = listOf(
            extras.getCharSequence("android.text")?.toString(),
            extras.getCharSequence("android.bigText")?.toString(),
            extras.getCharSequence("android.subText")?.toString()
        ).filterNotNull().joinToString(" ").replace(Regex("\\s+"), " ").trim().take(4000)

        if (text.length < 3 || sensitiveSignal.containsMatchIn(title + " " + text) ||
            !paymentSignal.containsMatchIn(title + " " + text)) return

        val keySource = "${sbn.packageName}|$title|$text|${sbn.postTime}"
        val key = MessageDigest.getInstance("SHA-256")
            .digest(keySource.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        Thread {
            val connection = (URL("$baseUrl/api/device-events").openConnection() as HttpURLConnection)
            try {
                connection.requestMethod = "POST"
                connection.connectTimeout = 12000
                connection.readTimeout = 12000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Authorization", "Bearer $token")
                val payload = JSONObject()
                    .put("source_package", sbn.packageName)
                    .put("notification_key", key)
                    .put("title", title)
                    .put("notification_text", text)
                    .put("posted_at", sbn.postTime)
                connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                // Response intentionally not logged: notification text may contain financial details.
                connection.inputStream?.close()
            } catch (_: Exception) {
                // No sensitive notification content is written to Android logs.
            } finally {
                connection.disconnect()
            }
        }.start()
    }
}