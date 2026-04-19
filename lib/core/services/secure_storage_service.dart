import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStorageService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );

  static const _privateKeyKey = 'e2e_private_key';
  static const _publicKeyKey  = 'e2e_public_key';
  static const _chatKeyPrefix = 'chat_key_';
  static const _chatIdsIndex  = 'chat_key_ids';

  // ── RSA keys ──────────────────────────────────────────────────────────────

  static Future<void> savePrivateKey(String key) async {
    debugPrint('[SecureStorage] savePrivateKey: ${key.length}c');
    await _storage.write(key: _privateKeyKey, value: key);
    debugPrint('[SecureStorage] savePrivateKey ✅');
  }

  static Future<String?> getPrivateKey() async {
    final val = await _storage.read(key: _privateKeyKey);
    debugPrint('[SecureStorage] getPrivateKey: ${val == null ? "null ❌" : "${val.length}c ✅"}');
    return val;
  }

  static Future<void> savePublicKey(String key) async {
    debugPrint('[SecureStorage] savePublicKey: ${key.length}c');
    await _storage.write(key: _publicKeyKey, value: key);
    debugPrint('[SecureStorage] savePublicKey ✅');
  }

  static Future<String?> getPublicKey() async {
    final val = await _storage.read(key: _publicKeyKey);
    debugPrint('[SecureStorage] getPublicKey: ${val == null ? "null ❌" : "${val.length}c ✅"}');
    return val;
  }

  static Future<bool> hasKeys() async {
    final priv = await getPrivateKey();
    final result = priv != null && priv.isNotEmpty;
    debugPrint('[SecureStorage] hasKeys: $result');
    return result;
  }

  // ── Chat keys (AES-256) ───────────────────────────────────────────────────

  static Future<void> saveChatKey(int chatId, Uint8List key) async {
    debugPrint('[SecureStorage] saveChatKey: chat=$chatId key=${key.length}B');
    await _storage.write(
      key: '$_chatKeyPrefix$chatId',
      value: base64Encode(key),
    );
    await _addChatIdToIndex(chatId);
    debugPrint('[SecureStorage] saveChatKey ✅ chat=$chatId');
  }

  static Future<Uint8List?> getChatKey(int chatId) async {
    final s = await _storage.read(key: '$_chatKeyPrefix$chatId');
    if (s == null) {
      debugPrint('[SecureStorage] getChatKey: chat=$chatId → null ❌');
      return null;
    }
    try {
      final bytes = base64Decode(s);
      debugPrint('[SecureStorage] getChatKey: chat=$chatId → ${bytes.length}B ✅');
      return bytes;
    } catch (e) {
      debugPrint('[SecureStorage] getChatKey: chat=$chatId → ❌ base64 decode failed: $e');
      return null;
    }
  }

  static Future<void> deleteChatKey(int chatId) async {
    debugPrint('[SecureStorage] deleteChatKey: chat=$chatId');
    await _storage.delete(key: '$_chatKeyPrefix$chatId');
    await _removeChatIdFromIndex(chatId);
    debugPrint('[SecureStorage] deleteChatKey ✅ chat=$chatId');
  }

  static Future<void> _addChatIdToIndex(int chatId) async {
    final raw = await _storage.read(key: _chatIdsIndex) ?? '';
    final ids = raw.isEmpty ? <String>{} : raw.split(',').toSet();
    ids.add(chatId.toString());
    await _storage.write(key: _chatIdsIndex, value: ids.join(','));
  }

  static Future<void> _removeChatIdFromIndex(int chatId) async {
    final raw = await _storage.read(key: _chatIdsIndex) ?? '';
    if (raw.isEmpty) return;
    final ids = raw.split(',').toSet()..remove(chatId.toString());
    await _storage.write(key: _chatIdsIndex, value: ids.join(','));
  }

  // ── Произвольные секреты ──────────────────────────────────────────────────

  static Future<void> saveSecret(String key, String value) =>
      _storage.write(key: key, value: value);

  static Future<String?> getSecret(String key) => _storage.read(key: key);

  static Future<void> deleteSecret(String key) => _storage.delete(key: key);

  // ── Полная очистка (при logout) ───────────────────────────────────────────

  static Future<void> clearAll() async {
    debugPrint('[SecureStorage] clearAll: deleting all stored secrets');
    await _storage.deleteAll();
    debugPrint('[SecureStorage] clearAll ✅');
  }
}
