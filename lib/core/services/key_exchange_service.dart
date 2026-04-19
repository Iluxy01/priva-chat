// ─── Обмен симметричными ключами чатов через WebSocket ───────────────────────

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import '../constants/app_constants.dart';
import '../crypto/encryption_service.dart';
import 'chat_service.dart';
import 'local_storage_service.dart';
import 'secure_storage_service.dart';
import 'websocket_service.dart';

class KeyExchangeService {
  KeyExchangeService._();
  static final KeyExchangeService instance = KeyExchangeService._();

  static const mediaTypeBundle  = 'key_bundle';
  static const mediaTypeRequest = 'key_request';

  final _uuid = const Uuid();

  StreamSubscription<WsSystemMessage>? _sub;

  /// Анти-спам: не чаще одного key_request в 10 секунд на чат.
  final Map<int, DateTime> _lastRequestAt = {};

  // ── Инициализация ─────────────────────────────────────────────────────────

  void init() {
    _sub?.cancel();
    _sub = WebSocketService.instance.onSystemMessage.listen(_onSystemMessage);
    debugPrint('[KeyExchange] ✅ Service started — listening for key_bundle / key_request');
  }

  Future<void> dispose() async {
    await _sub?.cancel();
    _sub = null;
    debugPrint('[KeyExchange] Service disposed');
  }

  // ── Публичные методы ──────────────────────────────────────────────────────

  Future<Uint8List?> getChatKey(int chatId) async {
    final key = await SecureStorageService.getChatKey(chatId);
    debugPrint('[KeyExchange] getChatKey(chat=$chatId): ${key == null ? "null ❌" : "${key.length}B ✅"}');
    return key;
  }

  /// Расшифровывает входящее WS-сообщение.
  Future<String> decryptIncoming(WsMessage msg) async {
    debugPrint('[KeyExchange] decryptIncoming: chat=${msg.chatId} sender=${msg.senderId} '
        'iv=${msg.iv?.length ?? "null"} contentLen=${msg.encryptedContent.length}');

    final iv = msg.iv;
    if (iv == null || iv.isEmpty) {
      debugPrint('[KeyExchange] decryptIncoming: no IV → treating as plaintext (legacy)');
      return msg.encryptedContent;
    }

    final key = await SecureStorageService.getChatKey(msg.chatId);
    if (key == null) {
      debugPrint('[KeyExchange] decryptIncoming: ⚠️  no chat key for chat=${msg.chatId} '
          '— sending key_request to sender=${msg.senderId}');
      requestKey(chatId: msg.chatId, senderId: msg.senderId);
      return '[🔒 ожидание ключа шифрования…]';
    }

    try {
      final plaintext = EncryptionService.decryptMessage(
        cipherB64: msg.encryptedContent,
        ivB64:     iv,
        chatKey:   key,
      );
      debugPrint('[KeyExchange] decryptIncoming ✅ chat=${msg.chatId}');
      return plaintext;
    } catch (e) {
      debugPrint('[KeyExchange] decryptIncoming ❌ FAILED for chat=${msg.chatId}: $e');
      requestKey(chatId: msg.chatId, senderId: msg.senderId);
      return '[🔒 не удалось расшифровать]';
    }
  }

  /// Гарантирует наличие ключа. Если нет — генерирует и рассылает bundle.
  Future<Uint8List?> ensureChatKey({
    required int chatId,
    required List<int> memberUserIds,
  }) async {
    debugPrint('[KeyExchange] ensureChatKey: chat=$chatId members=$memberUserIds');

    final existing = await SecureStorageService.getChatKey(chatId);
    if (existing != null) {
      debugPrint('[KeyExchange] ensureChatKey: key already exists for chat=$chatId ✅');
      return existing;
    }

    debugPrint('[KeyExchange] ensureChatKey: no key yet for chat=$chatId — generating new AES-256...');
    final key = EncryptionService.generateChatKey();
    await SecureStorageService.saveChatKey(chatId, key);
    debugPrint('[KeyExchange] ensureChatKey: key saved locally, sending bundle to $memberUserIds');

    await _sendBundle(chatId: chatId, chatKey: key, recipientIds: memberUserIds);
    return key;
  }

  /// Сигнал отправителю, что у нас нет ключа.
  Future<void> requestKey({required int chatId, required int senderId}) async {
    final last = _lastRequestAt[chatId];
    if (last != null && DateTime.now().difference(last).inSeconds < 10) {
      debugPrint('[KeyExchange] requestKey: throttled for chat=$chatId (last=${DateTime.now().difference(last).inSeconds}s ago)');
      return;
    }
    _lastRequestAt[chatId] = DateTime.now();
    debugPrint('[KeyExchange] requestKey → chat=$chatId sender=$senderId');

    WebSocketService.instance.sendMessage(
      chatId:           chatId,
      tempId:           'kr_${_uuid.v4()}',
      encryptedContent: '',
      recipientIds:     [senderId],
      mediaType:        mediaTypeRequest,
    );
  }

  /// Принудительно переотправить bundle (после добавления участника).
  Future<void> reshareKey({
    required int chatId,
    required List<int> memberUserIds,
  }) async {
    debugPrint('[KeyExchange] reshareKey: chat=$chatId members=$memberUserIds');
    final key = await SecureStorageService.getChatKey(chatId);
    if (key == null) {
      debugPrint('[KeyExchange] reshareKey: no key — calling ensureChatKey');
      await ensureChatKey(chatId: chatId, memberUserIds: memberUserIds);
      return;
    }
    await _sendBundle(chatId: chatId, chatKey: key, recipientIds: memberUserIds);
  }

  Future<void> dropChatKey(int chatId) async {
    await SecureStorageService.deleteChatKey(chatId);
    _lastRequestAt.remove(chatId);
    debugPrint('[KeyExchange] dropChatKey: removed key for chat=$chatId');
  }

  // ── Входящие системные сообщения ──────────────────────────────────────────

  Future<void> _onSystemMessage(WsSystemMessage msg) async {
    debugPrint('[KeyExchange] _onSystemMessage: type=${msg.mediaType} chat=${msg.chatId} sender=${msg.senderId}');
    try {
      switch (msg.mediaType) {
        case mediaTypeBundle:
          await _handleBundle(msg);
          break;
        case mediaTypeRequest:
          await _handleRequest(msg);
          break;
        default:
          debugPrint('[KeyExchange] _onSystemMessage: unknown mediaType=${msg.mediaType}');
      }
    } catch (e, st) {
      debugPrint('[KeyExchange] _onSystemMessage ERROR: $e\n$st');
    }
  }

  Future<void> _handleBundle(WsSystemMessage msg) async {
    debugPrint('[KeyExchange] _handleBundle: chat=${msg.chatId} contentLen=${msg.encryptedContent.length}');

    if (msg.encryptedContent.isEmpty) {
      debugPrint('[KeyExchange] _handleBundle: empty content — skipping');
      return;
    }

    Map<String, dynamic> payload;
    try {
      payload = jsonDecode(msg.encryptedContent) as Map<String, dynamic>;
      debugPrint('[KeyExchange] _handleBundle: keys in bundle = ${payload.keys.toList()}');
    } catch (e) {
      debugPrint('[KeyExchange] _handleBundle: ❌ JSON parse failed: $e');
      return;
    }

    final myId = await _myUserId();
    if (myId == null) {
      debugPrint('[KeyExchange] _handleBundle: ❌ cannot get myUserId');
      return;
    }
    debugPrint('[KeyExchange] _handleBundle: myUserId=$myId, looking for key...');

    final wrapped = payload[myId.toString()];
    if (wrapped is! String) {
      debugPrint('[KeyExchange] _handleBundle: ⚠️  no entry for myId=$myId in bundle. '
          'Available ids: ${payload.keys.toList()}');
      return;
    }

    debugPrint('[KeyExchange] _handleBundle: found wrapped key (${wrapped.length}c), unwrapping...');
    if (!EncryptionService.hasKeys) {
      debugPrint('[KeyExchange] _handleBundle: ❌ EncryptionService has no keys! Calling ensureKeys...');
      await EncryptionService.ensureKeys();
    }

    try {
      final chatKey = EncryptionService.unwrapChatKey(wrapped);
      await SecureStorageService.saveChatKey(msg.chatId, chatKey);
      debugPrint('[KeyExchange] _handleBundle: ✅ chat key adopted for chat=${msg.chatId} (${chatKey.length}B)');
    } catch (e) {
      debugPrint('[KeyExchange] _handleBundle: ❌ unwrap failed: $e');
    }
  }

  Future<void> _handleRequest(WsSystemMessage msg) async {
    debugPrint('[KeyExchange] _handleRequest: chat=${msg.chatId} requester=${msg.senderId}');
    final key = await SecureStorageService.getChatKey(msg.chatId);
    if (key == null) {
      debugPrint('[KeyExchange] _handleRequest: ⚠️  no key to share for chat=${msg.chatId}');
      return;
    }
    debugPrint('[KeyExchange] _handleRequest: sending bundle to requester=${msg.senderId}');
    await _sendBundle(chatId: msg.chatId, chatKey: key, recipientIds: [msg.senderId]);
  }

  // ── Утилиты ───────────────────────────────────────────────────────────────

  Future<void> _sendBundle({
    required int chatId,
    required Uint8List chatKey,
    required List<int> recipientIds,
  }) async {
    debugPrint('[KeyExchange] _sendBundle: chat=$chatId recipients=$recipientIds');
    if (recipientIds.isEmpty) {
      debugPrint('[KeyExchange] _sendBundle: no recipients — skip');
      return;
    }

    final publicKeys = await _collectPublicKeys(chatId, recipientIds);
    debugPrint('[KeyExchange] _sendBundle: collected ${publicKeys.length}/${recipientIds.length} public keys');

    if (publicKeys.isEmpty) {
      debugPrint('[KeyExchange] _sendBundle: ⚠️  no public keys found — cannot wrap. '
          'Possible cause: server /users/search did not return public_key field.');
      return;
    }

    final wrappedMap = <String, String>{};
    for (final entry in publicKeys.entries) {
      try {
        wrappedMap[entry.key.toString()] =
            EncryptionService.wrapChatKey(chatKey, entry.value);
        debugPrint('[KeyExchange] _sendBundle: wrapped key for user=${entry.key} ✅');
      } catch (e) {
        debugPrint('[KeyExchange] _sendBundle: ❌ wrap failed for user=${entry.key}: $e');
      }
    }

    if (wrappedMap.isEmpty) {
      debugPrint('[KeyExchange] _sendBundle: ❌ all wraps failed — not sending');
      return;
    }

    final ok = WebSocketService.instance.sendMessage(
      chatId:           chatId,
      tempId:           'kb_${_uuid.v4()}',
      encryptedContent: jsonEncode(wrappedMap),
      recipientIds:     publicKeys.keys.toList(),
      mediaType:        mediaTypeBundle,
    );
    debugPrint(ok
        ? '[KeyExchange] _sendBundle ✅ sent bundle to users=${wrappedMap.keys.toList()}'
        : '[KeyExchange] _sendBundle ❌ WS offline — bundle not sent');
  }

  Future<Map<int, String>> _collectPublicKeys(
    int chatId,
    List<int> recipientIds,
  ) async {
    debugPrint('[KeyExchange] _collectPublicKeys: chatId=$chatId ids=$recipientIds');
    final result = <int, String>{};

    for (final id in recipientIds) {
      final contact = await LocalStorageService.instance.getContact(id);
      final pk = contact?.publicKey;
      if (pk != null && pk.isNotEmpty) {
        result[id] = pk;
        debugPrint('[KeyExchange] _collectPublicKeys: user=$id pk from local cache ✅ (${pk.length}c)');
      } else {
        debugPrint('[KeyExchange] _collectPublicKeys: user=$id — no pk in local cache, will fetch from server');
      }
    }

    final missing = recipientIds.where((id) => !result.containsKey(id)).toList();
    if (missing.isEmpty) return result;

    debugPrint('[KeyExchange] _collectPublicKeys: fetching members for chat=$chatId (missing pks: $missing)');
    try {
      final members = await ChatService.getChatMembers(chatId);
      debugPrint('[KeyExchange] _collectPublicKeys: getChatMembers returned ${members.length} members');
      for (final m in members) {
        debugPrint('[KeyExchange] _collectPublicKeys:   member id=${m.id} pk=${m.publicKey == null ? "null ❌" : "${m.publicKey!.length}c ✅"}');
        if (missing.contains(m.id) && m.publicKey != null && m.publicKey!.isNotEmpty) {
          result[m.id] = m.publicKey!;
          await LocalStorageService.instance.saveContact(
            id: m.id, username: m.username, displayName: m.displayName,
            avatarUrl: m.avatarUrl, publicKey: m.publicKey, lastSeen: m.lastSeen,
          );
        }
      }
    } catch (e) {
      debugPrint('[KeyExchange] _collectPublicKeys: ❌ getChatMembers failed: $e');
    }

    debugPrint('[KeyExchange] _collectPublicKeys: result — ${result.length} keys collected');
    return result;
  }

  Future<int?> _myUserId() async {
    final prefs = await SharedPreferences.getInstance();
    final id = prefs.getInt(AppConstants.userIdKey);
    debugPrint('[KeyExchange] _myUserId: $id');
    return id;
  }
}
