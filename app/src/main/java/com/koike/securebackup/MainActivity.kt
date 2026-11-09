package com.koike.securebackup

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.koike.securebackup.backup.BackupService
import com.koike.securebackup.backup.EngineState
import com.koike.securebackup.backup.JobProgress
import com.koike.securebackup.data.PassphraseStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { MainScreen() } }
    }
}

/** Result of checking whether the backup destination already holds a set. */
enum class DestCheck { NotChecked, Checking, New, Existing, Failed }

/**
 * The confirmation entry is only meaningful for a brand-new set: there the
 * typed passphrase becomes the set's passphrase unchecked, so the two
 * entries must match. For an existing set the engine verifies the
 * passphrase against the set's check block before writing anything.
 */
fun passphraseConfirmationOk(isNewSet: Boolean, passphrase: String, confirm: String): Boolean =
    !isNewSet || passphrase == confirm

private fun formatBytes(b: Long): String = when {
    b >= 1L shl 30 -> "%.1f GB".format(b / (1L shl 30).toDouble())
    b >= 1L shl 20 -> "%.1f MB".format(b / (1L shl 20).toDouble())
    b >= 1L shl 10 -> "%.1f KB".format(b / (1L shl 10).toDouble())
    else -> "$b B"
}

private fun folderLabel(context: android.content.Context, uri: Uri?): String {
    if (uri == null) return "未選択"
    val doc = try { DocumentFile.fromTreeUri(context, uri) } catch (e: Exception) { null }
    return doc?.name ?: uri.lastPathSegment ?: uri.toString()
}

/** Folder names need a provider query, so fetch them off the UI thread and cache per Uri. */
@Composable
private fun rememberFolderLabel(uri: Uri?): String {
    val context = LocalContext.current
    var label by remember(uri) { mutableStateOf(if (uri == null) "未選択" else "…") }
    LaunchedEffect(uri) {
        if (uri != null) {
            label = withContext(Dispatchers.IO) { folderLabel(context, uri) }
        }
    }
    return label
}

@Composable
private fun MainScreen() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("prefs", android.content.Context.MODE_PRIVATE) }

    var passphrase by remember { mutableStateOf("") }
    var showPass by remember { mutableStateOf(false) }
    var rememberPass by remember { mutableStateOf(false) }
    var passphraseConfirm by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    // Register the weekly-backup reminder check. Guarded: a scheduling
    // failure must never take the app down (v1.6 crashed at launch on the
    // user's device when this ran unguarded in onCreate).
    LaunchedEffect(Unit) {
        runCatching { com.koike.securebackup.backup.BackupReminderWorker.schedule(context) }
    }

    // preload a device-saved passphrase, if any
    LaunchedEffect(Unit) {
        val saved = withContext(Dispatchers.IO) { PassphraseStore.load(context) }
        if (saved != null) {
            passphrase = saved
            // A stored passphrase was verified against its set when saved,
            // so it can pre-confirm a new set as well.
            passphraseConfirm = saved
            rememberPass = true
        }
    }

    fun persistPassphraseChoice() {
        val toSave = if (rememberPass) passphrase else null
        scope.launch(Dispatchers.IO) {
            if (toSave != null) PassphraseStore.save(context, toSave) else PassphraseStore.clear(context)
        }
    }
    var backupDest by remember { mutableStateOf(prefs.getString("backupDest", null)?.let(Uri::parse)) }

    // Whether the chosen backup destination already holds a set decides if
    // the passphrase must be typed twice (new set = a typo would become the
    // set's passphrase with nothing to check it against).
    var destCheck by remember { mutableStateOf(DestCheck.NotChecked) }
    LaunchedEffect(backupDest) {
        if (backupDest == null) {
            destCheck = DestCheck.NotChecked
        } else {
            destCheck = DestCheck.Checking
            destCheck = withContext(Dispatchers.IO) {
                try {
                    val root = DocumentFile.fromTreeUri(context, backupDest!!)
                    if (root?.findFile("BACKUP_META.json") == null) DestCheck.New else DestCheck.Existing
                } catch (e: Exception) {
                    DestCheck.Failed
                }
            }
        }
    }
    var restoreSrc by remember { mutableStateOf(prefs.getString("restoreSrc", null)?.let(Uri::parse)) }
    var restoreDest by remember { mutableStateOf(prefs.getString("restoreDest", null)?.let(Uri::parse)) }
    var formError by remember { mutableStateOf<String?>(null) }

    var hasAccess by remember { mutableStateOf(checkAccess(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) hasAccess = checkAccess(context)
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    fun onPicked(key: String, uri: Uri?, set: (Uri?) -> Unit) {
        if (uri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            } catch (e: Exception) { /* some providers don't persist; best effort */ }
            prefs.edit().putString(key, uri.toString()).apply()
        }
        set(uri)
    }

    val pickBackupDest = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) {
        onPicked("backupDest", it) { u -> backupDest = u }
    }
    val pickRestoreSrc = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) {
        onPicked("restoreSrc", it) { u -> restoreSrc = u }
    }
    val pickRestoreDest = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) {
        onPicked("restoreDest", it) { u -> restoreDest = u }
    }
    val requestNotif = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val requestLegacyStorage = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { hasAccess = checkAccess(context) }

    val progressState = EngineState.flow.collectAsState()
    val running by remember { derivedStateOf { progressState.value.running } }
    val backupDestLabel = rememberFolderLabel(backupDest)
    val restoreSrcLabel = rememberFolderLabel(restoreSrc)
    val restoreDestLabel = rememberFolderLabel(restoreDest)

    fun ensureNotifPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotif.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("暗号化バックアップ", style = MaterialTheme.typography.headlineSmall)
        Text(
            "共有ストレージ（内部ストレージ）内の全ファイルを、端末上で暗号化してから保存先フォルダへコピーします。" +
                "保存先に Google ドライブのフォルダを選べば、そのまま Drive へアップロードされます。",
            style = MaterialTheme.typography.bodySmall
        )

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("1. ファイルへのアクセス", style = MaterialTheme.typography.titleMedium)
                if (hasAccess) {
                    Text("許可済み ✓", style = MaterialTheme.typography.bodyMedium)
                } else {
                    Text("全ファイルへのアクセス許可が必要です。", style = MaterialTheme.typography.bodySmall)
                    Button(onClick = {
                        if (Build.VERSION.SDK_INT >= 30) {
                            val i = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                                .setData(Uri.parse("package:${context.packageName}"))
                            try { context.startActivity(i) } catch (e: Exception) {
                                context.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                            }
                        } else {
                            requestLegacyStorage.launch(
                                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                            )
                        }
                    }) { Text("設定を開く") }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("2. パスフレーズ", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("暗号化パスフレーズ（6文字以上）") },
                    singleLine = true,
                    visualTransformation = if (showPass) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        OutlinedButton(onClick = { showPass = !showPass }) {
                            Text(if (showPass) "隠す" else "表示")
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                )
                Row {
                    Checkbox(checked = rememberPass, onCheckedChange = { rememberPass = it })
                    Text("パスフレーズをこの端末に保存する", Modifier.padding(top = 12.dp))
                }
                Text(
                    "保存する場合、パスフレーズはAndroidキーストアの鍵で暗号化して端末内に置きます（次回から入力不要）。" +
                        "ただし端末のロックを解除できる人はバックアップも開けるようになるので、共有端末ではオフ推奨。" +
                        "他の端末で復元するときは結局パスフレーズが必要なので、忘れた場合に備えた控えは別途どうぞ。",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("3. バックアップ", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { pickBackupDest.launch(null) }) { Text("保存先フォルダ") }
                    Text(backupDestLabel, Modifier.padding(top = 10.dp))
                }
                Text(
                    "Google ドライブに保存する場合は、フォルダ選択画面の左上のメニューから Google ドライブを開き、保存先フォルダを選んでください。",
                    style = MaterialTheme.typography.bodySmall
                )
                if (destCheck == DestCheck.New) {
                    Text(
                        "このフォルダには既存のバックアップがありません。新規作成では打ち間違えたパスフレーズがそのまま正規のものになってしまうため、確認用にもう一度入力してください。",
                        style = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = passphraseConfirm,
                        onValueChange = { passphraseConfirm = it },
                        label = { Text("パスフレーズ（確認）") },
                        singleLine = true,
                        visualTransformation = if (showPass) VisualTransformation.None else PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
                Button(
                    enabled = !running,
                    onClick = {
                        formError = when {
                            !hasAccess -> "先に全ファイルアクセスを許可してください"
                            passphrase.length < 6 -> "パスフレーズは6文字以上にしてください"
                            backupDest == null -> "保存先フォルダを選んでください"
                            destCheck == DestCheck.Checking || destCheck == DestCheck.NotChecked ->
                                "保存先フォルダを確認しています。少し待ってからもう一度押してください"
                            !passphraseConfirmationOk(destCheck == DestCheck.New, passphrase, passphraseConfirm) ->
                                "パスフレーズ（確認）が一致しません"
                            else -> null
                        }
                        if (formError == null) {
                            ensureNotifPermission()
                            persistPassphraseChoice()
                            BackupService.startBackup(context, backupDest!!, passphrase)
                        }
                    }
                ) { Text("バックアップ開始") }
                Text(
                    "2回目以降は、変更されたファイルだけを更新します（差分バックアップ）。",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("4. 復元", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { pickRestoreSrc.launch(null) }) { Text("バックアップ元") }
                    Text(restoreSrcLabel, Modifier.padding(top = 10.dp))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { pickRestoreDest.launch(null) }) { Text("復元先フォルダ") }
                    Text(restoreDestLabel, Modifier.padding(top = 10.dp))
                }
                Button(
                    enabled = !running,
                    onClick = {
                        formError = when {
                            passphrase.length < 6 -> "バックアップ時と同じパスフレーズを入力してください"
                            restoreSrc == null -> "バックアップ元フォルダを選んでください"
                            restoreDest == null -> "復元先フォルダを選んでください"
                            else -> null
                        }
                        if (formError == null) {
                            ensureNotifPermission()
                            persistPassphraseChoice()
                            BackupService.startRestore(context, restoreSrc!!, restoreDest!!, passphrase)
                        }
                    }
                ) { Text("復元開始") }
            }
        }

        if (formError != null) {
            Text(formError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        ProgressCard(progressState.value)

        Text(
            "対象外: 他アプリの内部データ（/Android/data 等）とシステム領域は、root化していない端末ではアプリから読めません。" +
                "写真・動画・ドキュメント・ダウンロードなど共有ストレージ内のファイルが対象です。",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(24.dp))
    }
}

/** Isolated so progress updates don't recompose the whole screen. */
@Composable
private fun ProgressCard(progress: JobProgress) {
    if (!progress.running && progress.summary == null) return
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("進捗", style = MaterialTheme.typography.titleMedium)
            if (progress.totalBytes > 0) {
                LinearProgressIndicator(
                    progress = { (progress.doneBytes.toFloat() / progress.totalBytes).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            Text(
                "${progress.phase}　${progress.doneFiles}/${progress.totalFiles} 件　" +
                    "${formatBytes(progress.doneBytes)} / ${formatBytes(progress.totalBytes)}"
            )
            if (progress.current.isNotEmpty()) {
                Text(progress.current, style = MaterialTheme.typography.bodySmall)
            }
            if (progress.running) {
                OutlinedButton(onClick = { EngineState.cancelRequested = true }) { Text("中止") }
            }
            if (progress.summary != null) {
                Text(progress.summary!!, style = MaterialTheme.typography.bodyMedium)
            }
            if (progress.errors.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text("エラー ${progress.errors.size}件:", style = MaterialTheme.typography.bodySmall)
                for (e in progress.errors.take(50)) {
                    Text("・$e", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private fun checkAccess(context: android.content.Context): Boolean =
    if (Build.VERSION.SDK_INT >= 30) {
        Environment.isExternalStorageManager()
    } else {
        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    }
