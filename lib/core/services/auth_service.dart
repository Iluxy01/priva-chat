import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/constants/app_constants.dart';
import '../../features/auth/models/user_model.dart';
import '../crypto/encryption_service.dart';
import 'secure_storage_service.dart';

class AuthService {
  static const _base = AppConstants.serverUrl;

  // ── Регистрация ────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> register({
    required String username,
    required String displayName,
    required String password,
  }) async {
    debugPrint('[AuthService] register: username=$username');
    final res = await http
        .post(
          Uri.parse('$_base/auth/register'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'username': username,
            'display_name': displayName,
            'password': password,
          }),
        )
        .timeout(const Duration(seconds: 15));

    debugPrint('[AuthService] register → ${res.statusCode}: ${res.body.length}c');
    final body = jsonDecode(res.body);
    if (res.statusCode == 201) {
      await _saveSession(body['token'], body['user']);
      await _bootstrapEncryption();
      return {'success': true, 'user': UserModel.fromJson(body['user'])};
    }
    debugPrint('[AuthService] register ❌ error: ${body['error']}');
    return {'success': false, 'error': body['error'] ?? 'Ошибка регистрации'};
  }

  // ── Вход ───────────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> login({
    required String username,
    required String password,
  }) async {
    debugPrint('[AuthService] login: username=$username');
    final res = await http
        .post(
          Uri.parse('$_base/auth/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'username': username, 'password': password}),
        )
        .timeout(const Duration(seconds: 15));

    debugPrint('[AuthService] login → ${res.statusCode}');
    final body = jsonDecode(res.body);
    if (res.statusCode == 200) {
      await _saveSession(body['token'], body['user']);
      await _bootstrapEncryption();
      return {'success': true, 'user': UserModel.fromJson(body['user'])};
    }
    debugPrint('[AuthService] login ❌ error: ${body['error']}');
    return {'success': false, 'error': body['error'] ?? 'Неверный логин или пароль'};
  }

  // ── Получить профиль ───────────────────────────────────────────────────────
  static Future<UserModel?> getMe() async {
    final token = await getToken();
    if (token == null) return null;

    final res = await http.get(
      Uri.parse('$_base/users/me'),
      headers: {'Authorization': 'Bearer $token'},
    ).timeout(const Duration(seconds: 10));

    debugPrint('[AuthService] getMe → ${res.statusCode}');
    if (res.statusCode == 200) {
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final userData = body.containsKey('user')
          ? body['user'] as Map<String, dynamic>
          : body;
      return UserModel.fromJson(userData);
    }
    return null;
  }

  // ── Обновить профиль ───────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> updateProfile({
    String? displayName,
    String? status,
    String? publicKey,
  }) async {
    final token = await getToken();
    if (token == null) return {'success': false, 'error': 'Не авторизован'};

    final body = <String, dynamic>{};
    if (displayName != null) body['display_name'] = displayName;
    if (status != null) body['status'] = status;
    if (publicKey != null) body['public_key'] = publicKey;

    debugPrint('[AuthService] updateProfile: fields=${body.keys.toList()}');
    final res = await http.put(
      Uri.parse('$_base/users/me'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token',
      },
      body: jsonEncode(body),
    ).timeout(const Duration(seconds: 10));

    debugPrint('[AuthService] updateProfile → ${res.statusCode}');
    if (res.statusCode == 200) {
      final respBody = jsonDecode(res.body) as Map<String, dynamic>;
      final userData = respBody.containsKey('user')
          ? respBody['user'] as Map<String, dynamic>
          : respBody;
      return {'success': true, 'user': UserModel.fromJson(userData)};
    }
    return {'success': false, 'error': 'Ошибка обновления'};
  }

  // ── Выход ──────────────────────────────────────────────────────────────────
  static Future<void> logout() async {
    debugPrint('[AuthService] logout: clearing session and keys');
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(AppConstants.tokenKey);
    await prefs.remove(AppConstants.userIdKey);
    await SecureStorageService.clearAll();
    await EncryptionService.reset();
    debugPrint('[AuthService] logout ✅');
  }

  // ── Утилиты ────────────────────────────────────────────────────────────────
  static Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(AppConstants.tokenKey);
  }

  static Future<bool> isLoggedIn() async {
    final token = await getToken();
    return token != null && token.isNotEmpty;
  }

  static Future<void> _saveSession(String token, Map<String, dynamic> user) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(AppConstants.tokenKey, token);
    await prefs.setInt(AppConstants.userIdKey, user['id']);
    debugPrint('[AuthService] _saveSession: userId=${user['id']}');
  }

  /// Инициализация E2E после входа/регистрации:
  ///   1) генерируем (или загружаем) RSA-ключи
  ///   2) публичный ключ публикуем через POST /auth/update-public-key
  static Future<void> _bootstrapEncryption() async {
    debugPrint('[AuthService] _bootstrapEncryption: start');
    try {
      await EncryptionService.ensureKeys();

      final pk = EncryptionService.myPublicKey;
      if (pk == null) {
        debugPrint('[AuthService] _bootstrapEncryption: ❌ myPublicKey is null after ensureKeys()');
        return;
      }
      debugPrint('[AuthService] _bootstrapEncryption: got public key (${pk.length}c), uploading...');

      try {
        await _uploadPublicKey(pk);
        debugPrint('[AuthService] _bootstrapEncryption: ✅ public key uploaded');
      } catch (e) {
        debugPrint('[AuthService] _bootstrapEncryption: ⚠️  upload failed (non-fatal): $e');
      }
    } catch (e) {
      debugPrint('[AuthService] _bootstrapEncryption: ❌ FATAL: $e');
    }
  }

  /// POST /auth/update-public-key — единственный эндпоинт, который
  /// реально сохраняет public_key в БД (PUT /users/me его игнорирует).
  static Future<void> _uploadPublicKey(String publicKey) async {
    final token = await getToken();
    if (token == null) {
      debugPrint('[AuthService] _uploadPublicKey: no token — skip');
      return;
    }

    debugPrint('[AuthService] _uploadPublicKey: POST /auth/update-public-key (pkLen=${publicKey.length}c)');
    final res = await http
        .post(
          Uri.parse('$_base/auth/update-public-key'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $token',
          },
          body: jsonEncode({'public_key': publicKey}),
        )
        .timeout(const Duration(seconds: 10));

    debugPrint('[AuthService] _uploadPublicKey → ${res.statusCode}: ${res.body}');
    if (res.statusCode != 200) {
      throw Exception('upload-public-key → ${res.statusCode}: ${res.body}');
    }
  }
}
