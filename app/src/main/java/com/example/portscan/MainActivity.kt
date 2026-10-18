package com.example.portscan

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

private const val PORT = 443
private const val TIMEOUT_MS = 1500
private const val MAX_CONCURRENCY = 100
private const val MAX_RANGE_SIZE = 65_536L
private const val MAX_TOTAL_HOSTS = 100_000

// ---------- Парсинг адресов ----------

fun ipToLong(ip: String): Long {
    val parts = ip.trim().split(".")
    require(parts.size == 4) { "Некорректный IP: $ip" }
    val nums = parts.map { it.toIntOrNull() ?: throw IllegalArgumentException("Некорректный IP: $ip") }
    require(nums.all { it in 0..255 }) { "Некорректный IP: $ip" }
    return nums.fold(0L) { acc, x -> (acc shl 8) or x.toLong() }
}

fun longToIp(v: Long): String =
    listOf(24, 16, 8, 0).joinToString(".") { ((v shr it) and 0xFF).toString() }

/** Разбирает текст с диапазонами (CIDR, A-B или одиночный IP) в список адресов без дублей. */
fun parseRanges(input: String): List<String> {
    val result = LinkedHashSet<String>()
    for (raw in input.lines()) {
        val line = raw.trim()
        if (line.isEmpty()) continue

        val (start, end) = when {
            "/" in line -> {
                val (ip, bits) = line.split("/", limit = 2)
                val prefix = bits.trim().toIntOrNull()
                require(prefix != null && prefix in 0..32) { "Некорректная маска: $line" }
                val hostMask = (1L shl (32 - prefix)) - 1
                val base = ipToLong(ip) and hostMask.inv() and 0xFFFFFFFFL
                base to (base or hostMask)
            }
            "-" in line -> {
                val (a, b) = line.split("-", limit = 2)
                ipToLong(a) to ipToLong(b)
            }
            else -> ipToLong(line).let { it to it }
        }

        require(end >= start) { "Неверный диапазон: $line" }
        require(end - start < MAX_RANGE_SIZE) { "Диапазон больше 65 536 адресов: $line" }
        require(result.size + (end - start + 1) <= MAX_TOTAL_HOSTS) {
            "Всего адресов больше $MAX_TOTAL_HOSTS, уменьшите список"
        }
        for (i in start..end) result += longToIp(i)
    }
    return result.toList()
}

// ---------- Проверка порта ----------

fun isPortOpen(ip: String): Boolean = try {
    Socket().use { s ->
        s.connect(InetSocketAddress(ip, PORT), TIMEOUT_MS)
        true
    }
} catch (e: Exception) {
    false
}

suspend fun scan(
    ips: List<String>,
    onProgress: () -> Unit,
    onOpen: (String) -> Unit
) = coroutineScope {
    val sem = Semaphore(MAX_CONCURRENCY)
    ips.map { ip ->
        launch(Dispatchers.IO) {
            sem.withPermit {
                val open = isPortOpen(ip)
                withContext(Dispatchers.Main) {
                    onProgress()
                    if (open) onOpen(ip)
                }
            }
        }
    }.joinAll()
}

// ---------- UI ----------

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme { ScanScreen() }
        }
    }
}

@Composable
fun ScanScreen() {
    var input by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var done by remember { mutableIntStateOf(0) }
    var total by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    val live = remember { mutableStateListOf<String>() }
    val scope = rememberCoroutineScope()

    Column(
        Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = { Text("Диапазоны (по одному на строку)") },
            placeholder = { Text("192.168.1.0/24\n10.0.0.1-10.0.0.50\n1.2.3.4") },
            modifier = Modifier.fillMaxWidth(),
            minLines = 3,
            maxLines = 6,
            enabled = !scanning
        )

        Spacer(Modifier.height(12.dp))

        Button(
            enabled = !scanning && input.isNotBlank(),
            onClick = {
                error = null
                live.clear()
                val ips = try {
                    parseRanges(input)
                } catch (e: Exception) {
                    error = e.message ?: "Ошибка разбора"
                    null
                }
                if (ips != null && ips.isNotEmpty()) {
                    scanning = true
                    done = 0
                    total = ips.size
                    scope.launch {
                        try {
                            scan(
                                ips = ips,
                                onProgress = { done++ },
                                onOpen = { ip -> live.add(ip) }
                            )
                        } finally {
                            val sorted = live.sortedBy { ipToLong(it) }
                            live.clear()
                            live.addAll(sorted)
                            scanning = false
                        }
                    }
                }
            }
        ) {
            Text(if (scanning) "Сканирование..." else "Сканировать")
        }

        error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
        }

        if (total > 0) {
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { done.toFloat() / total },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(4.dp))
            Text("Проверено $done из $total, открыт 443: ${live.size}")
        }

        Spacer(Modifier.height(12.dp))

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            verticalArrangement = Arrangement.Top
        ) {
            items(live) { ip ->
                Text(
                    text = ip,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }
}
