import 'dart:async';
import 'package:flutter/foundation.dart';
import 'websocket_service.dart';

/// Хранит статусы онлайн/офлайн пользователей, полученные через WebSocket.
/// Используй [isOnline] / [lastSeen] в UI.
class PresenceService extends ChangeNotifier {
  static final PresenceService _instance = PresenceService._();
  static PresenceService get instance => _instance;
  PresenceService._();

  /// userId → true = online
  final Map<int, bool> _online = {};

  /// userId → последнее время появления (ISO8601)
  final Map<int, String> _lastSeen = {};

  StreamSubscription<WsPresence>? _sub;

  // ── Инициализация ──────────────────────────────────────────────────────────

  void init() {
    _sub?.cancel();
    _sub = WebSocketService.instance.onPresence.listen(_handlePresence);
  }

  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  // ── Геттеры ────────────────────────────────────────────────────────────────

  bool isOnline(int userId) => _online[userId] ?? false;

  String? lastSeen(int userId) => _lastSeen[userId];

  // ── Обработка события ──────────────────────────────────────────────────────

  void _handlePresence(WsPresence event) {
    _online[event.userId] = event.status == 'online';
    _lastSeen[event.userId] = event.at;
    notifyListeners();
    debugPrint('[Presence] user ${event.userId} → ${event.status}');
  }

  /// Принудительно пометить как онлайн (например, после загрузки чата)
  void markOnline(int userId) {
    if (_online[userId] != true) {
      _online[userId] = true;
      notifyListeners();
    }
  }

  /// Принудительно пометить как офлайн
  void markOffline(int userId, {String? at}) {
    _online[userId] = false;
    if (at != null) _lastSeen[userId] = at;
    notifyListeners();
  }
}
