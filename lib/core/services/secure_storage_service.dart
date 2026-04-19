import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Хранит приватный ключ шифрования в защищённом хранилище ОС
/// (Keychain на iOS, Keystore на Android).
class SecureStorageService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _privateKeyKey = 'e2e_private_key';
  static const _publicKeyKey  = 'e2e_public_key';

  // ── Ключи шифрования ───────────────────────────────────────────────────────

  static Future<void> savePrivateKey(String key) =>
      _storage.write(key: _privateKeyKey, value: key);

  static Future<String?> getPrivateKey() =>
      _storage.read(key: _privateKeyKey);

  static Future<void> savePublicKey(String key) =>
      _storage.write(key: _publicKeyKey, value: key);

  static Future<String?> getPublicKey() =>
      _storage.read(key: _publicKeyKey);

  static Future<bool> hasKeys() async {
    final priv = await getPrivateKey();
    return priv != null && priv.isNotEmpty;
  }

  // ── Произвольные секреты (например, ключи групповых чатов) ────────────────

  static Future<void> saveSecret(String key, String value) =>
      _storage.write(key: key, value: value);

  static Future<String?> getSecret(String key) =>
      _storage.read(key: key);

  static Future<void> deleteSecret(String key) =>
      _storage.delete(key: key);

  // ── Очистить всё (при выходе) ─────────────────────────────────────────────

  static Future<void> clearAll() => _storage.deleteAll();
}
