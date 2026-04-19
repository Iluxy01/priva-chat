// ─── Высокоуровневый API шифрования ──────────────────────────────────────────

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:pointycastle/export.dart';

import '../services/secure_storage_service.dart';
import 'crypto_utils.dart';

class EncryptedPayload {
  final String cipher; // base64
  final String iv;     // base64
  const EncryptedPayload({required this.cipher, required this.iv});
}

class EncryptionService {
  static RSAPublicKey?  _pub;
  static RSAPrivateKey? _priv;
  static String?        _pubSerialized;

  // ── Инициализация ──────────────────────────────────────────────────────────

  static Future<void> ensureKeys() async {
    if (_priv != null && _pub != null) {
      debugPrint('[EncryptionService] ensureKeys: keys already in memory ✅');
      return;
    }

    debugPrint('[EncryptionService] ensureKeys: loading from SecureStorage...');
    final priv = await SecureStorageService.getPrivateKey();
    final pub  = await SecureStorageService.getPublicKey();

    if (priv != null && pub != null) {
      debugPrint('[EncryptionService] Found stored keys (priv=${priv.length}c pub=${pub.length}c), deserializing...');
      try {
        _priv = CryptoUtils.deserializePrivateKey(priv);
        _pub  = CryptoUtils.deserializePublicKey(pub);
        _pubSerialized = pub;
        debugPrint('[EncryptionService] ✅ Keys loaded from storage');
        return;
      } catch (e) {
        debugPrint('[EncryptionService] ⚠️  Stored keys corrupted ($e) — regenerating');
      }
    } else {
      debugPrint('[EncryptionService] No stored keys found (priv=${priv == null ? "null" : "ok"} pub=${pub == null ? "null" : "ok"})');
    }

    debugPrint('[EncryptionService] Generating new RSA-2048 keypair (runs in isolate ~1-2s)...');
    final serialized = await compute(_generateInIsolate, 2048);
    _priv = CryptoUtils.deserializePrivateKey(serialized['private']!);
    _pub  = CryptoUtils.deserializePublicKey(serialized['public']!);
    _pubSerialized = serialized['public'];

    await SecureStorageService.savePrivateKey(serialized['private']!);
    await SecureStorageService.savePublicKey(serialized['public']!);
    debugPrint('[EncryptionService] ✅ New keypair generated & persisted');
  }

  static String? get myPublicKey {
    debugPrint('[EncryptionService] myPublicKey getter: ${_pubSerialized == null ? "null ❌" : "${_pubSerialized!.length}c ✅"}');
    return _pubSerialized;
  }

  static bool get hasKeys => _priv != null && _pub != null;

  static Future<void> reset() async {
    debugPrint('[EncryptionService] reset() — clearing in-memory keys');
    _priv = null;
    _pub  = null;
    _pubSerialized = null;
  }

  // ── Chat keys ──────────────────────────────────────────────────────────────

  static Uint8List generateChatKey() {
    final key = CryptoUtils.randomBytes(32);
    debugPrint('[EncryptionService] generateChatKey ✅ (32B AES-256)');
    return key;
  }

  static String wrapChatKey(Uint8List chatKey, String recipientPublicKey) {
    debugPrint('[EncryptionService] wrapChatKey: chatKey=${chatKey.length}B, recipientPK=${recipientPublicKey.length}c');
    try {
      final pub     = CryptoUtils.deserializePublicKey(recipientPublicKey);
      final wrapped = CryptoUtils.rsaEncrypt(chatKey, pub);
      final b64     = base64Encode(wrapped);
      debugPrint('[EncryptionService] wrapChatKey ✅ wrapped=${b64.length}c');
      return b64;
    } catch (e) {
      debugPrint('[EncryptionService] ❌ wrapChatKey FAILED: $e');
      rethrow;
    }
  }

  static Uint8List unwrapChatKey(String wrappedBase64) {
    debugPrint('[EncryptionService] unwrapChatKey: input=${wrappedBase64.length}c');
    final priv = _priv;
    if (priv == null) {
      debugPrint('[EncryptionService] ❌ unwrapChatKey — _priv is NULL (ensureKeys() not called?)');
      throw StateError('Private key not initialized — call ensureKeys() first');
    }
    try {
      final bytes   = base64Decode(wrappedBase64);
      final chatKey = CryptoUtils.rsaDecrypt(bytes, priv);
      debugPrint('[EncryptionService] unwrapChatKey ✅ chatKey=${chatKey.length}B');
      return chatKey;
    } catch (e) {
      debugPrint('[EncryptionService] ❌ unwrapChatKey FAILED: $e');
      rethrow;
    }
  }

  // ── Messages ───────────────────────────────────────────────────────────────

  static EncryptedPayload encryptMessage(String plaintext, Uint8List chatKey) {
    debugPrint('[EncryptionService] encryptMessage: plainLen=${plaintext.length}c chatKey=${chatKey.length}B');
    final iv    = CryptoUtils.randomBytes(12);
    final plain = Uint8List.fromList(utf8.encode(plaintext));
    final ct    = CryptoUtils.aesGcmEncrypt(key: chatKey, iv: iv, plain: plain);
    final payload = EncryptedPayload(
      cipher: base64Encode(ct),
      iv:     base64Encode(iv),
    );
    debugPrint('[EncryptionService] encryptMessage ✅ cipher=${payload.cipher.length}c iv=${payload.iv.length}c');
    return payload;
  }

  static String decryptMessage({
    required String cipherB64,
    required String ivB64,
    required Uint8List chatKey,
  }) {
    debugPrint('[EncryptionService] decryptMessage: cipher=${cipherB64.length}c iv=${ivB64.length}c chatKey=${chatKey.length}B');
    try {
      final ct    = base64Decode(cipherB64);
      final iv    = base64Decode(ivB64);
      final plain = CryptoUtils.aesGcmDecrypt(key: chatKey, iv: iv, cipherText: ct);
      final text  = utf8.decode(plain);
      debugPrint('[EncryptionService] decryptMessage ✅ plain="${text.length > 40 ? text.substring(0, 40) + "…" : text}"');
      return text;
    } catch (e) {
      debugPrint('[EncryptionService] ❌ decryptMessage FAILED: $e');
      rethrow;
    }
  }
}

// ── Isolate helper ────────────────────────────────────────────────────────────

Map<String, String> _generateInIsolate(int bitLength) {
  final pair = CryptoUtils.generateRsaKeyPair(bitLength: bitLength);
  return {
    'public':  CryptoUtils.serializePublicKey(pair.publicKey),
    'private': CryptoUtils.serializePrivateKey(pair.privateKey),
  };
}
