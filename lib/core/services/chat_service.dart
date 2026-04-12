import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;
import '../constants/app_constants.dart';
import '../services/auth_service.dart';
import '../../features/auth/models/user_model.dart';

class ChatService {
  static const _base = AppConstants.serverUrl;

  static Future<Map<String, String>> _headers() async {
    final token = await AuthService.getToken();
    return {
      'Content-Type': 'application/json',
      if (token != null) 'Authorization': 'Bearer $token',
    };
  }

  static List<dynamic> _extractList(dynamic body, String key) {
    if (body is List) return body;
    if (body is Map)  return (body[key] as List<dynamic>?) ?? [];
    return [];
  }

  // ── Поиск пользователей ────────────────────────────────────────────────────

  static Future<List<UserModel>> searchUsers(String query) async {
    if (query.trim().length < 2) return [];
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) {
      throw const ChatException('Не авторизован — войди заново');
    }
    final uri = Uri.parse('$_base/users/search')
        .replace(queryParameters: {'q': query.trim()});
    debugPrint('[ChatService] GET $uri');
    http.Response res;
    try {
      res = await http.get(uri, headers: headers).timeout(const Duration(seconds: 10));
    } on Exception catch (e) {
      throw ChatException('Нет соединения: $e');
    }
    debugPrint('[ChatService] search → ${res.statusCode}');
    switch (res.statusCode) {
      case 200:
        final body = jsonDecode(res.body);
        return _extractList(body, 'users')
            .map((u) => UserModel.fromJson(u as Map<String, dynamic>))
            .toList();
      case 401: throw const ChatException('Сессия устарела — войди заново');
      case 404: throw const ChatException('Маршрут не найден — проверь URL сервера');
      default:  throw ChatException('Ошибка сервера: ${res.statusCode}');
    }
  }

  // ── Список чатов ───────────────────────────────────────────────────────────

  static Future<List<ServerChat>> getChats() async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) return [];
    http.Response res;
    try {
      res = await http.get(Uri.parse('$_base/chats'), headers: headers)
          .timeout(const Duration(seconds: 15));
    } on Exception { return []; }
    if (res.statusCode != 200) return [];
    final body = jsonDecode(res.body);
    return _extractList(body, 'chats')
        .map((c) => ServerChat.fromJson(c as Map<String, dynamic>))
        .toList();
  }

  // ── Создать личный чат ─────────────────────────────────────────────────────

  static Future<int> createDirectChat(int targetUserId) async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) {
      throw const ChatException('Не авторизован');
    }
    http.Response res;
    try {
      res = await http.post(
        Uri.parse('$_base/chats/direct'),
        headers: headers,
        body: jsonEncode({'target_user_id': targetUserId}),
      ).timeout(const Duration(seconds: 10));
    } on Exception catch (e) {
      throw ChatException('Нет соединения: $e');
    }
    debugPrint('[ChatService] createDirectChat → ${res.statusCode}: ${res.body}');
    if (res.statusCode == 200 || res.statusCode == 201) {
      final body = jsonDecode(res.body);
      if (body is int) return body;
      if (body is Map) {
        final id = body['chat_id'] ?? body['id'];
        if (id != null) return (id as num).toInt();
      }
    }
    throw ChatException('Ошибка создания чата: ${res.statusCode}');
  }

  // ── Создать групповой чат ──────────────────────────────────────────────────

  static Future<int> createGroupChat({
    required String name,
    required List<int> memberIds,
  }) async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) {
      throw const ChatException('Не авторизован');
    }
    http.Response res;
    try {
      res = await http.post(
        Uri.parse('$_base/chats/group'),
        headers: headers,
        body: jsonEncode({'name': name, 'member_ids': memberIds}),
      ).timeout(const Duration(seconds: 10));
    } on Exception catch (e) {
      throw ChatException('Нет соединения: $e');
    }
    debugPrint('[ChatService] createGroupChat → ${res.statusCode}: ${res.body}');
    if (res.statusCode == 200 || res.statusCode == 201) {
      final body = jsonDecode(res.body);
      if (body is int) return body;
      if (body is Map) {
        final id = body['chat_id'] ?? body['id'];
        if (id != null) return (id as num).toInt();
      }
    }
    throw ChatException('Ошибка создания группы: ${res.statusCode}');
  }

  // ── Добавить участника в группу ────────────────────────────────────────────

  static Future<void> addMemberToGroup(int chatId, int userId) async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) {
      throw const ChatException('Не авторизован');
    }
    http.Response res;
    try {
      res = await http.post(
        Uri.parse('$_base/chats/$chatId/members'),
        headers: headers,
        body: jsonEncode({'user_id': userId}),
      ).timeout(const Duration(seconds: 10));
    } on Exception catch (e) {
      throw ChatException('Нет соединения: $e');
    }
    if (res.statusCode != 200 && res.statusCode != 201) {
      final body = jsonDecode(res.body);
      throw ChatException((body is Map ? body['error'] : null) ?? 'Ошибка добавления');
    }
  }

  // ── Участники чата ─────────────────────────────────────────────────────────

  static Future<List<UserModel>> getChatMembers(int chatId) async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) return [];
    http.Response res;
    try {
      res = await http.get(Uri.parse('$_base/chats/$chatId/members'), headers: headers)
          .timeout(const Duration(seconds: 10));
    } on Exception { return []; }
    if (res.statusCode != 200) return [];
    final body = jsonDecode(res.body);
    return _extractList(body, 'members')
        .map((u) => UserModel.fromJson(u as Map<String, dynamic>))
        .toList();
  }

  // ── Удалить чат ────────────────────────────────────────────────────────────

  static Future<void> deleteChat(int chatId) async {
    final headers = await _headers();
    if (!headers.containsKey('Authorization')) return;
    try {
      await http.delete(
        Uri.parse('$_base/chats/$chatId'),
        headers: headers,
      ).timeout(const Duration(seconds: 10));
    } catch (_) {}
    // Локальная очистка — на стороне вызывающего кода
  }
}

// ── Исключение ────────────────────────────────────────────────────────────────

class ChatException implements Exception {
  final String message;
  const ChatException(this.message);
  @override
  String toString() => message;
}

// ── DTO с сервера ─────────────────────────────────────────────────────────────

class ServerChat {
  final int id;
  final String type;
  final String? name;
  final String? avatarUrl;
  final List<UserModel> members;

  const ServerChat({
    required this.id, required this.type,
    this.name, this.avatarUrl, required this.members,
  });

  factory ServerChat.fromJson(Map<String, dynamic> j) {
    final raw = j['members'] as List<dynamic>? ?? [];
    return ServerChat(
      id:        j['id'] as int,
      type:      j['type'] as String,
      name:      j['name'] as String?,
      avatarUrl: j['avatar_url'] as String?,
      members:   raw.map((m) => UserModel.fromJson(m as Map<String, dynamic>)).toList(),
    );
  }
}
