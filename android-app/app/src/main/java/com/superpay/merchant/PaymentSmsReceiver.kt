package com.superpay.merchant

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Telephony
import android.telephony.SmsMessage
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class PaymentSmsReceiver : BroadcastReceiver() {
    private val baseUrl = "https://swappaykassma.vercel.app"
    private val paymentSignal = Regex("(?i)(credited|received|deposited|debited|paid|payment|transfer|transaction|upi|deposit|withdrawal|refund|INR|Rs\\.?|₹)")
    private val sensitiveSignal = Regex("(?i)(\\bOTP\\b|one.time.password|password|\\bPIN\\b|verification code|login code|CVV|card number)")

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (context.checkSelfPermission(Manifest.permission.RECEIVE_SMS) != PackageManager.PERMISSION_GRANTED) return
        val prefs = context.getSharedPreferences("paykassma_session", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("sms_monitoring_enabled", false)) return
        val token = prefs.getString("token", null) ?: return
        val messages = try {
            Telephony.Sms.Intents.getMessagesFromIntent(intent).toList()
        } catch (_: Exception) { emptyList() }
        if (messages.isEmpty()) return

        // Multipart SMS parts are grouped by sender and timestamp; only payment-like text is uploaded.
        val grouped = messages.groupBy { it.originatingAddress.orEmpty() to (it.timestampMillis / 60_000L) }
        grouped.forEach { (key, parts) ->
            val sender = key.first.take(100)
            val body = parts.joinToString("") { it.messageBody.orEmpty() }
                .replace(Regex("\\s+"), " ").trim().take(2000)
            val timestamp = parts.minOfOrNull { it.timestampMillis } ?: System.currentTimeMillis()
            if (sender.isBlank() || body.length < 8 || !paymentSignal.containsMatchIn(body) || sensitiveSignal.containsMatchIn(body)) return@forEach
            val digestInput = "$sender|$body|$timestamp"
            val hash = MessageDigest.getInstance("SHA-256")
                .digest(digestInput.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            Thread {
                val connection = URL("$baseUrl/api/device-events").openConnection() as HttpURLConnection
                try {
                    connection.requestMethod = "POST"
                    connection.connectTimeout = 12000
                    connection.readTimeout = 12000
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.setRequestProperty("Authorization", "Bearer $token")
                    val payload = JSONObject()
                        .put("action", "payment_sms")
                        .put("sender", sender)
                        .put("message_text", body)
                        .put("message_hash", hash)
                        .put("received_at", timestamp)
                    connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                    val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
                    stream?.close()
                } catch (_: Exception) {
                    // Never log SMS content, sender, or financial details.
                } finally {
                    connection.disconnect()
                }
            }.start()
        }
    }
}
