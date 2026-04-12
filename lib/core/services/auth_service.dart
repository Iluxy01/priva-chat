import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../../core/constants/app_constants.dart';
import '../../features/auth/models/user_model.dart';

class AuthService {
  static const _base = AppConstants.serverUrl;

  // ── Регистрация ────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> register({
    required String username,
    required String displayName,
    required String password,
  }) async {
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

    final body = jsonDecode(res.body);
    if (res.statusCode == 201) {
      await _saveSession(body['token'], body['user']);
      return {'success': true, 'user': UserModel.fromJson(body['user'])};
    }
    return {'success': false, 'error': body['error'] ?? 'Ошибка регистрации'};
  }

  // ── Вход ───────────────────────────────────────────────────────────────────
  static Future<Map<String, dynamic>> login({
    required String username,
    required String password,
  }) async {
    final res = await http
        .post(
          Uri.parse('$_base/auth/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'username': username, 'password': password}),
        )
        .timeout(const Duration(seconds: 15));

    final body = jsonDecode(res.body);
    if (res.statusCode == 200) {
      await _saveSession(body['token'], body['user']);
      return {'success': true, 'user': UserModel.fromJson(body['user'])};
    }
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

    if (res.statusCode == 200) {
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      // Сервер возвращает { "user": {...} }
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
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(AppConstants.tokenKey);
    await prefs.remove(AppConstants.userIdKey);
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
  }
}
