import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Хранит ключи шифрования в защищённом хранилище ОС
/// (Keychain на iOS, Keystore на Android).
class SecureStorageService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _privateKeyKey = 'e2e_private_key';
  static const _publicKeyKey  = 'e2e_public_key';
  static const _chatKeyPrefix = 'chat_key_'; // ключ чата = "chat_key_{chatId}"

  // ── RSA ключи пользователя ─────────────────────────────────────────────────

  static Future<void> savePrivateKey(String key) async {
    print('[SecureStorage] savePrivateKey: ${key.length} chars');
    await _storage.write(key: _privateKeyKey, value: key);
    print('[SecureStorage] savePrivateKey: OK ✅');
  }

  static Future<String?> getPrivateKey() async {
    final val = await _storage.read(key: _privateKeyKey);
    print('[SecureStorage] getPrivateKey: ${val == null ? "null ❌" : "${val.length}c ✅"}');
    return val;
  }

  static Future<void> savePublicKey(String key) async {
    print('[SecureStorage] savePublicKey: ${key.length} chars');
    await _storage.write(key: _publicKeyKey, value: key);
    print('[SecureStorage] savePublicKey: OK ✅');
  }

  static Future<String?> getPublicKey() async {
    final val = await _storage.read(key: _publicKeyKey);
    print('[SecureStorage] getPublicKey: ${val == null ? "null ❌" : "${val.length}c ✅"}');
    return val;
  }

  static Future<bool> hasKeys() async {
    final priv = await getPrivateKey();
    return priv != null && priv.isNotEmpty;
  }

  // ── AES ключи чатов ────────────────────────────────────────────────────────
  // Ключ чата хранится как base64 строка под ключом "chat_key_{chatId}"

  static Future<void> saveChatKey(int chatId, Uint8List key) async {
    final storageKey = '${_chatKeyPrefix}$chatId';
    final b64 = base64Encode(key);
    print('[SecureStorage] saveChatKey: chat=$chatId key=${key.length}B → "$storageKey" (${b64.length}c)');
    await _storage.write(key: storageKey, value: b64);
    print('[SecureStorage] saveChatKey: OK ✅');
  }

  static Future<Uint8List?> getChatKey(int chatId) async {
    final storageKey = '${_chatKeyPrefix}$chatId';
    final val = await _storage.read(key: storageKey);
    if (val == null) {
      print('[SecureStorage] getChatKey: chat=$chatId → null ❌');
      return null;
    }
    try {
      final bytes = base64Decode(val);
      print('[SecureStorage] getChatKey: chat=$chatId → ${bytes.length}B ✅');
      return bytes;
    } catch (e) {
      print('[SecureStorage] getChatKey: chat=$chatId → DECODE ERROR: $e ❌');
      return null;
    }
  }

  static Future<void> deleteChatKey(int chatId) async {
    final storageKey = '${_chatKeyPrefix}$chatId';
    print('[SecureStorage] deleteChatKey: chat=$chatId → "$storageKey"');
    await _storage.delete(key: storageKey);
    print('[SecureStorage] deleteChatKey: OK ✅');
  }

  // ── Произвольные секреты ───────────────────────────────────────────────────

  static Future<void> saveSecret(String key, String value) async {
    print('[SecureStorage] saveSecret: key="$key" value=${value.length}c');
    await _storage.write(key: key, value: value);
  }

  static Future<String?> getSecret(String key) async {
    final val = await _storage.read(key: key);
    print('[SecureStorage] getSecret: key="$key" → ${val == null ? "null" : "${val.length}c"}');
    return val;
  }

  static Future<void> deleteSecret(String key) async {
    print('[SecureStorage] deleteSecret: key="$key"');
    await _storage.delete(key: key);
  }

  // ── Очистить всё (при выходе) ─────────────────────────────────────────────

  static Future<void> clearAll() async {
    print('[SecureStorage] clearAll: удаляем все секреты...');
    await _storage.deleteAll();
    print('[SecureStorage] clearAll: OK ✅');
  }
}
