import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:web_socket_channel/status.dart' as ws_status;
import '../constants/app_constants.dart';
import '../services/auth_service.dart';

// ─── Статус соединения ────────────────────────────────────────────────────────

enum WsStatus { disconnected, connecting, connected, reconnecting }

// ─── Модели входящих событий ─────────────────────────────────────────────────

class WsMessage {
  final int chatId;
  final String? tempId;
  final int senderId;
  final String encryptedContent;
  final String mediaType;
  final String? iv;
  final String sentAt;

  const WsMessage({
    required this.chatId,
    this.tempId,
    required this.senderId,
    required this.encryptedContent,
    required this.mediaType,
    this.iv,
    required this.sentAt,
  });

  factory WsMessage.fromJson(Map<String, dynamic> j) => WsMessage(
        chatId:           (j['chat_id'] as num).toInt(),
        tempId:           j['temp_id'] as String?,
        senderId:         int.parse(j['sender_id'].toString()),
        encryptedContent: j['encrypted_content'] as String,
        mediaType:        (j['media_type'] as String?) ?? 'text',
        iv:               j['iv'] as String?,
        sentAt:           j['sent_at'] as String,
      );
}

class WsAck {
  final String? tempId;
  final int chatId;
  final bool delivered;
  final String sentAt;

  const WsAck({
    this.tempId,
    required this.chatId,
    required this.delivered,
    required this.sentAt,
  });

  factory WsAck.fromJson(Map<String, dynamic> j) => WsAck(
        tempId:    j['temp_id'] as String?,
        chatId:    (j['chat_id'] as num).toInt(),
        delivered: (j['delivered'] as bool?) ?? false,
        sentAt:    j['sent_at'] as String,
      );
}

class WsTyping {
  final int chatId;
  final int senderId;
  final bool isTyping;

  const WsTyping({
    required this.chatId,
    required this.senderId,
    required this.isTyping,
  });

  factory WsTyping.fromJson(Map<String, dynamic> j) => WsTyping(
        chatId:   (j['chat_id'] as num).toInt(),
        senderId: int.parse(j['sender_id'].toString()),
        isTyping: (j['is_typing'] as bool?) ?? false,
      );
}

class WsRead {
  final int chatId;
  final int readerId;
  final String? upToTempId;

  const WsRead({
    required this.chatId,
    required this.readerId,
    this.upToTempId,
  });

  factory WsRead.fromJson(Map<String, dynamic> j) => WsRead(
        chatId:      (j['chat_id'] as num).toInt(),
        readerId:    int.parse(j['reader_id'].toString()),
        upToTempId:  j['up_to_temp_id'] as String?,
      );
}

class WsPresence {
  final int userId;
  final String status; // 'online' | 'offline'
  final String at;

  const WsPresence({
    required this.userId,
    required this.status,
    required this.at,
  });

  factory WsPresence.fromJson(Map<String, dynamic> j) => WsPresence(
        userId: int.parse(j['user_id'].toString()),
        status: j['status'] as String,
        at:     j['at'] as String,
      );
}

// ─── Сам сервис ───────────────────────────────────────────────────────────────

class WebSocketService extends ChangeNotifier {
  // Singleton
  static final WebSocketService _instance = WebSocketService._();
  static WebSocketService get instance => _instance;
  WebSocketService._();

  // ── Состояние ──────────────────────────────────────────────────────────────

  WsStatus _status = WsStatus.disconnected;
  WsStatus get status => _status;
  bool get isConnected => _status == WsStatus.connected;

  WebSocketChannel? _channel;

  // Reconnect
  Timer? _reconnectTimer;
  Timer? _pingTimer;
  int _reconnectAttempts = 0;
  static const _maxReconnectDelay = Duration(seconds: 60);
  static const _basePingInterval = Duration(seconds: 25);

  // ── Стримы событий ─────────────────────────────────────────────────────────

  final _messageCtrl   = StreamController<WsMessage>.broadcast();
  final _ackCtrl       = StreamController<WsAck>.broadcast();
  final _typingCtrl    = StreamController<WsTyping>.broadcast();
  final _readCtrl      = StreamController<WsRead>.broadcast();
  final _presenceCtrl  = StreamController<WsPresence>.broadcast();

  Stream<WsMessage>  get onMessage  => _messageCtrl.stream;
  Stream<WsAck>      get onAck      => _ackCtrl.stream;
  Stream<WsTyping>   get onTyping   => _typingCtrl.stream;
  Stream<WsRead>     get onRead     => _readCtrl.stream;
  Stream<WsPresence> get onPresence => _presenceCtrl.stream;

  // ── Подключение ────────────────────────────────────────────────────────────

  Future<void> connect() async {
    if (_status == WsStatus.connected || _status == WsStatus.connecting) return;

    final token = await AuthService.getToken();
    if (token == null) {
      debugPrint('[WS] No token — skip connect');
      return;
    }

    _setStatus(WsStatus.connecting);

    try {
      final uri = Uri.parse('${AppConstants.wsUrl}/ws?token=$token');
      _channel = WebSocketChannel.connect(uri);

      // Ждём подтверждения соединения
      await _channel!.ready;

      _setStatus(WsStatus.connected);
      _reconnectAttempts = 0;
      _startPing();

      debugPrint('[WS] Connected ✅');

      // Слушаем входящие сообщения
      _channel!.stream.listen(
        _onData,
        onError: _onError,
        onDone: _onDone,
        cancelOnError: false,
      );
    } catch (e) {
      debugPrint('[WS] Connect error: $e');
      _setStatus(WsStatus.disconnected);
      _scheduleReconnect();
    }
  }

  void disconnect() {
    _reconnectTimer?.cancel();
    _pingTimer?.cancel();
    _reconnectTimer = null;
    _pingTimer = null;
    _reconnectAttempts = 0;
    _channel?.sink.close(ws_status.normalClosure);
    _channel = null;
    _setStatus(WsStatus.disconnected);
    debugPrint('[WS] Disconnected manually');
  }

  // ── Отправка сообщений ─────────────────────────────────────────────────────

  /// Отправить зашифрованное сообщение в чат
  bool sendMessage({
    required int chatId,
    required String tempId,
    required String encryptedContent,
    required List<int> recipientIds,
    String mediaType = 'text',
    String? iv,
  }) {
    return _send({
      'type': 'message',
      'chat_id': chatId,
      'temp_id': tempId,
      'encrypted_content': encryptedContent,
      'media_type': mediaType,
      'iv': iv,
      'recipient_ids': recipientIds,
    });
  }

  /// Индикатор печати
  bool sendTyping({
    required int chatId,
    required List<int> recipientIds,
    required bool isTyping,
  }) {
    return _send({
      'type': 'typing',
      'chat_id': chatId,
      'recipient_ids': recipientIds,
      'is_typing': isTyping,
    });
  }

  /// Прочитал до tempId
  bool sendRead({
    required int chatId,
    required int senderId,
    String? upToTempId,
  }) {
    return _send({
      'type': 'read',
      'chat_id': chatId,
      'sender_id': senderId,
      'up_to_temp_id': upToTempId,
    });
  }

  // ── Приём данных ───────────────────────────────────────────────────────────

  void _onData(dynamic raw) {
    Map<String, dynamic> json;
    try {
      json = jsonDecode(raw as String) as Map<String, dynamic>;
    } catch (_) {
      return;
    }

    final type = json['type'] as String?;
    debugPrint('[WS] ← $type');

    switch (type) {
      case 'message':
        _messageCtrl.add(WsMessage.fromJson(json));
        break;
      case 'message_ack':
        _ackCtrl.add(WsAck.fromJson(json));
        break;
      case 'typing':
        _typingCtrl.add(WsTyping.fromJson(json));
        break;
      case 'read':
        _readCtrl.add(WsRead.fromJson(json));
        break;
      case 'presence':
        _presenceCtrl.add(WsPresence.fromJson(json));
        break;
      case 'pong':
        // keepalive — ничего не делаем
        break;
      default:
        debugPrint('[WS] Unknown type: $type');
    }
  }

  void _onError(Object error) {
    debugPrint('[WS] Error: $error');
    _setStatus(WsStatus.disconnected);
    _stopPing();
    _scheduleReconnect();
  }

  void _onDone() {
    final closeCode = _channel?.closeCode;
    debugPrint('[WS] Connection closed (code: $closeCode)');
    _setStatus(WsStatus.disconnected);
    _stopPing();

    // 4001 = Unauthorized (сервер отклонил токен).
    // Не переподключаемся — токен невалиден, нужен повторный вход.
    if (closeCode == 4001) {
      debugPrint('[WS] Auth rejected by server — not reconnecting');
      return;
    }
    _scheduleReconnect();
  }

  // ── Reconnect ──────────────────────────────────────────────────────────────

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();

    // Экспоненциальная задержка: 1s, 2s, 4s, 8s, 16s, 32s, 60s (максимум)
    final delay = Duration(
      seconds: (1 << _reconnectAttempts.clamp(0, 6)).clamp(1, 60),
    );

    _reconnectAttempts++;
    _setStatus(WsStatus.reconnecting);

    debugPrint('[WS] Reconnect in ${delay.inSeconds}s (attempt $_reconnectAttempts)');

    _reconnectTimer = Timer(delay, () async {
      final token = await AuthService.getToken();
      if (token == null) {
        // Пользователь вышел — не переподключаемся
        _setStatus(WsStatus.disconnected);
        return;
      }
      _setStatus(WsStatus.disconnected);
      await connect();
    });
  }

  // ── Ping / Keepalive ───────────────────────────────────────────────────────

  void _startPing() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(_basePingInterval, (_) {
      if (_status == WsStatus.connected) {
        _send({'type': 'ping'});
      }
    });
  }

  void _stopPing() {
    _pingTimer?.cancel();
    _pingTimer = null;
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  bool _send(Map<String, dynamic> payload) {
    if (_channel == null || _status != WsStatus.connected) {
      debugPrint('[WS] Cannot send — not connected');
      return false;
    }
    try {
      _channel!.sink.add(jsonEncode(payload));
      return true;
    } catch (e) {
      debugPrint('[WS] Send error: $e');
      return false;
    }
  }

  void _setStatus(WsStatus s) {
    if (_status == s) return;
    _status = s;
    debugPrint('[WS] Status: $s');
    notifyListeners();
  }

  // ── Dispose ────────────────────────────────────────────────────────────────

  @override
  void dispose() {
    disconnect();
    _messageCtrl.close();
    _ackCtrl.close();
    _typingCtrl.close();
    _readCtrl.close();
    _presenceCtrl.close();
    super.dispose();
  }
}
