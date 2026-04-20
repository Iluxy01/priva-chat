import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../../core/constants/app_constants.dart';
import '../../features/auth/models/user_model.dart';
import '../../core/crypto/encryption_service.dart';

class AuthService {
  static const _base = AppConstants.serverUrl;

  // ── Регистрация ────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> register({
    required String username,
    required String displayName,
    required String password,
  }) async {
    // ШАГ 1: Генерируем RSA ключи ДО отправки на сервер
    print('[AuthService] register: шаг 1 — генерируем RSA ключи...');
    try {
      await EncryptionService.ensureKeys();
    } catch (e) {
      print('[AuthService] register: ❌ ошибка генерации ключей: $e');
      return {'success': false, 'error': 'Ошибка генерации ключей шифрования'};
    }

    final publicKey = EncryptionService.myPublicKey;
    print('[AuthService] register: public_key готов — ${publicKey?.length ?? 0} chars');

    if (publicKey == null) {
      print('[AuthService] register: ❌ publicKey == null после ensureKeys!');
      return {'success': false, 'error': 'Ключ шифрования не создан'};
    }

    // ШАГ 2: Регистрируем пользователя с public_key
    print('[AuthService] register: шаг 2 — POST /auth/register...');
    http.Response res;
    try {
      res = await http.post(
        Uri.parse('$_base/auth/register'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'username':     username,
          'display_name': displayName,
          'password':     password,
          'public_key':   publicKey, // ← отправляем ключ шифрования
        }),
      ).timeout(const Duration(seconds: 15));
    } catch (e) {
      print('[AuthService] register: ❌ сетевая ошибка: $e');
      return {'success': false, 'error': 'Нет соединения с сервером'};
    }

    print('[AuthService] register: сервер ответил ${res.statusCode}');

    final body = jsonDecode(res.body);
    if (res.statusCode == 201) {
      // ШАГ 3: Сохраняем сессию
      print('[AuthService] register: шаг 3 — сохраняем сессию...');
      await _saveSession(body['token'], body['user']);
      print('[AuthService] register: ✅ успешная регистрация');
      return {'success': true, 'user': UserModel.fromJson(body['user'])};
    }

    print('[AuthService] register: ❌ ошибка: ${body['error']}');
    return {'success': false, 'error': body['error'] ?? 'Ошибка регистрации'};
  }

  // ── Вход ───────────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> login({
    required String username,
    required String password,
  }) async {
    print('[AuthService] login: POST /auth/login для user=$username...');
    http.Response res;
    try {
      res = await http.post(
        Uri.parse('$_base/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'username': username, 'password': password}),
      ).timeout(const Duration(seconds: 15));
    } catch (e) {
      print('[AuthService] login: ❌ сетевая ошибка: $e');
      return {'success': false, 'error': 'Нет соединения с сервером'};
    }

    print('[AuthService] login: сервер ответил ${res.statusCode}');

    final body = jsonDecode(res.body);
    if (res.statusCode == 200) {
      // ШАГ 1: Сохраняем сессию
      print('[AuthService] login: шаг 1 — сохраняем сессию...');
      await _saveSession(body['token'], body['user']);

      // ШАГ 2: Загружаем (или генерируем) ключи шифрования
      print('[AuthService] login: шаг 2 — инициализируем ключи шифрования...');
      try {
        await EncryptionService.ensureKeys();
      } catch (e) {
        print('[AuthService] login: ⚠️ ошибка инициализации ключей: $e (продолжаем без шифрования)');
      }

      // ШАГ 3: Обновляем public_key на сервере (на случай если ключи пересозданы)
      final pubKey = EncryptionService.myPublicKey;
      if (pubKey != null) {
        print('[AuthService] login: шаг 3 — обновляем public_key на сервере (${pubKey.length}c)...');
        await _uploadPublicKey(pubKey, body['token'] as String);
      } else {
        print('[AuthService] login: шаг 3 — пропускаем обновление ключа (ключ null)');
      }

      print('[AuthService] login: ✅ успешный вход');
      return {
        'success': true,
        'user': UserModel.fromJson({
          'id':           body['user']['id'],
          'username':     body['user']['username'],
          'display_name': body['user']['display_name'],
          'public_key':   body['user']['public_key'],
          'avatar_url':   body['user']['avatar_url'],
          'status':       body['user']['status'],
        }),
      };
    }

    print('[AuthService] login: ❌ ошибка: ${body['error']}');
    return {'success': false, 'error': body['error'] ?? 'Неверный логин или пароль'};
  }

  // ── Загрузить public_key на сервер ─────────────────────────────────────────
  static Future<void> _uploadPublicKey(String publicKey, String token) async {
    print('[AuthService] _uploadPublicKey: POST /auth/update-public-key (${publicKey.length}c)...');
    try {
      final res = await http.post(
        Uri.parse('$_base/auth/update-public-key'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer $token',
        },
        body: jsonEncode({'public_key': publicKey}),
      ).timeout(const Duration(seconds: 10));
      print('[AuthService] _uploadPublicKey: сервер ответил ${res.statusCode} ✅');
    } catch (e) {
      print('[AuthService] _uploadPublicKey: ⚠️ ошибка: $e (некритично)');
    }
  }

  // ── Получить профиль ───────────────────────────────────────────────────────
  static Future<UserModel?> getMe() async {
    final token = await getToken();
    if (token == null) return null;

    final res = await http.get(
      Uri.parse('$_base/users/me'),
      headers: {'Authorization': 'Bearer $token'},
    ).timeout(const Duration(seconds: 10));

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
  }) async {
    final token = await getToken();
    if (token == null) return {'success': false, 'error': 'Не авторизован'};

    final body = <String, dynamic>{};
    if (displayName != null) body['display_name'] = displayName;
    if (status != null) body['status'] = status;

    final res = await http.put(
      Uri.parse('$_base/users/me'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token',
      },
      body: jsonEncode(body),
    ).timeout(const Duration(seconds: 10));

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
    print('[AuthService] logout: очищаем сессию...');
    await EncryptionService.reset();
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(AppConstants.tokenKey);
    await prefs.remove(AppConstants.userIdKey);
    print('[AuthService] logout: OK ✅');
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

  static Future<void> _saveSession(
      String token, Map<String, dynamic> user) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(AppConstants.tokenKey, token);
    await prefs.setInt(AppConstants.userIdKey, user['id']);
    print('[AuthService] _saveSession: userId=${user['id']} token saved ✅');
  }
}
