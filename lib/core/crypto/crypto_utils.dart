// ─── Low-level криптография на pointycastle ──────────────────────────────────

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:pointycastle/export.dart';

class CryptoUtils {
  static final Random _rand = Random.secure();

  static FortunaRandom _fortuna() {
    final fr = FortunaRandom();
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => _rand.nextInt(256)),
    );
    fr.seed(KeyParameter(seed));
    return fr;
  }

  static Uint8List randomBytes(int length) {
    return Uint8List.fromList(
      List<int>.generate(length, (_) => _rand.nextInt(256)),
    );
  }

  // ── RSA key generation ─────────────────────────────────────────────────────

  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateRsaKeyPair({
    int bitLength = 2048,
  }) {
    debugPrint('[CryptoUtils] 🔑 Generating RSA-$bitLength keypair...');
    final sw = Stopwatch()..start();
    final keyGen = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
          _fortuna(),
        ),
      );
    final pair = keyGen.generateKeyPair();
    sw.stop();
    debugPrint('[CryptoUtils] ✅ RSA keypair generated in ${sw.elapsedMilliseconds}ms');
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey,
    );
  }

  // ── Сериализация ключей ────────────────────────────────────────────────────

  static String serializePublicKey(RSAPublicKey pub) {
    final s = jsonEncode({
      'n': pub.modulus!.toRadixString(16),
      'e': pub.exponent!.toRadixString(16),
    });
    debugPrint('[CryptoUtils] serializePublicKey → ${s.length} chars');
    return s;
  }

  static RSAPublicKey deserializePublicKey(String data) {
    try {
      final m = jsonDecode(data) as Map<String, dynamic>;
      final key = RSAPublicKey(
        BigInt.parse(m['n'] as String, radix: 16),
        BigInt.parse(m['e'] as String, radix: 16),
      );
      debugPrint('[CryptoUtils] deserializePublicKey ✅ (${key.modulus!.bitLength}-bit)');
      return key;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ deserializePublicKey FAILED: $e');
      debugPrint('[CryptoUtils]   input preview: ${data.length > 80 ? data.substring(0, 80) : data}');
      rethrow;
    }
  }

  static String serializePrivateKey(RSAPrivateKey priv) {
    final s = jsonEncode({
      'n': priv.modulus!.toRadixString(16),
      'd': priv.privateExponent!.toRadixString(16),
      'p': priv.p!.toRadixString(16),
      'q': priv.q!.toRadixString(16),
    });
    debugPrint('[CryptoUtils] serializePrivateKey → ${s.length} chars');
    return s;
  }

  static RSAPrivateKey deserializePrivateKey(String data) {
    try {
      final m = jsonDecode(data) as Map<String, dynamic>;
      final key = RSAPrivateKey(
        BigInt.parse(m['n'] as String, radix: 16),
        BigInt.parse(m['d'] as String, radix: 16),
        BigInt.parse(m['p'] as String, radix: 16),
        BigInt.parse(m['q'] as String, radix: 16),
      );
      debugPrint('[CryptoUtils] deserializePrivateKey ✅ (${key.modulus!.bitLength}-bit)');
      return key;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ deserializePrivateKey FAILED: $e');
      rethrow;
    }
  }

  // ── RSA-OAEP ───────────────────────────────────────────────────────────────

  static Uint8List rsaEncrypt(Uint8List plain, RSAPublicKey key) {
    debugPrint('[CryptoUtils] rsaEncrypt plain=${plain.length}B');
    try {
      final cipher = OAEPEncoding(RSAEngine())
        ..init(true, PublicKeyParameter<RSAPublicKey>(key));
      final ct = cipher.process(plain);
      debugPrint('[CryptoUtils] rsaEncrypt ✅ cipher=${ct.length}B');
      return ct;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ rsaEncrypt FAILED: $e');
      rethrow;
    }
  }

  static Uint8List rsaDecrypt(Uint8List cipherText, RSAPrivateKey key) {
    debugPrint('[CryptoUtils] rsaDecrypt cipher=${cipherText.length}B');
    try {
      final cipher = OAEPEncoding(RSAEngine())
        ..init(false, PrivateKeyParameter<RSAPrivateKey>(key));
      final plain = cipher.process(cipherText);
      debugPrint('[CryptoUtils] rsaDecrypt ✅ plain=${plain.length}B');
      return plain;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ rsaDecrypt FAILED (wrong key? corrupt data?): $e');
      rethrow;
    }
  }

  // ── AES-256-GCM ────────────────────────────────────────────────────────────

  static Uint8List aesGcmEncrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List plain,
    Uint8List? aad,
  }) {
    debugPrint('[CryptoUtils] aesGcmEncrypt key=${key.length}B iv=${iv.length}B plain=${plain.length}B');
    try {
      final gcm = GCMBlockCipher(AESEngine())
        ..init(true, AEADParameters(KeyParameter(key), 128, iv, aad ?? Uint8List(0)));
      final ct = gcm.process(plain);
      debugPrint('[CryptoUtils] aesGcmEncrypt ✅ cipher=${ct.length}B (+16B GCM tag)');
      return ct;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ aesGcmEncrypt FAILED: $e');
      rethrow;
    }
  }

  static Uint8List aesGcmDecrypt({
    required Uint8List key,
    required Uint8List iv,
    required Uint8List cipherText,
    Uint8List? aad,
  }) {
    debugPrint('[CryptoUtils] aesGcmDecrypt key=${key.length}B iv=${iv.length}B cipher=${cipherText.length}B');
    try {
      final gcm = GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(key), 128, iv, aad ?? Uint8List(0)));
      final plain = gcm.process(cipherText);
      debugPrint('[CryptoUtils] aesGcmDecrypt ✅ plain=${plain.length}B');
      return plain;
    } catch (e) {
      debugPrint('[CryptoUtils] ❌ aesGcmDecrypt FAILED (tag mismatch / wrong key): $e');
      rethrow;
    }
  }
}
