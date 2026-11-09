# Secure Backup（暗号化バックアップ）

Android の共有ストレージ全体をパスフレーズで暗号化してバックアップする個人用アプリ。

- パッケージ: `com.koike.securebackup`
- 鍵導出: PBKDF2-HMAC-SHA256（60万回）→ AES-256-GCM（1MiB チャンクごとに認証）
- ファイル名は UUID 化し、目録（manifest.enc）自体も暗号化するため、保存先からは中身もファイル名も分からない
- 保存先は SAF のフォルダ選択（Google ドライブのフォルダを選べば Drive へ保存）
- 差分バックアップ（サイズ + mtime）、復元、フォアグラウンドサービスによる進捗表示、小ファイルのパック化に対応
- 対象外: 他アプリの内部データとシステム領域（root なしでは取得不可）

## ビルド

JDK 17 + Android SDK で `gradle :app:assembleDebug`。

署名鍵（`fullbackup.keystore`）と `local.properties` はリポジトリに含まれない。
リリース署名で上書きインストール可能に保つには、手元の鍵で署名すること。
