import 'package:drift/drift.dart';
import '../database/app_database.dart';

/// Удобная обёртка над AppDatabase.
/// Все экраны работают через этот сервис — не напрямую с БД.
class LocalStorageService {
  static final LocalStorageService _i = LocalStorageService._();
  static LocalStorageService get instance => _i;
  LocalStorageService._();

  late AppDatabase _db;

  void init(AppDatabase db) => _db = db;

  // ── Contacts ───────────────────────────────────────────────────────────────

  Future<void> saveContact({
    required int id,
    required String username,
    required String displayName,
    String? avatarUrl,
    String? status,
    String? publicKey,
    String? lastSeen,
  }) =>
      _db.upsertContact(ContactsCompanion(
        id:          Value(id),
        username:    Value(username),
        displayName: Value(displayName),
        avatarUrl:   Value(avatarUrl),
        status:      Value(status),
        publicKey:   Value(publicKey),
        lastSeen:    Value(lastSeen),
      ));

  Future<Contact?> getContact(int id) => _db.getContact(id);
  Future<List<Contact>> getAllContacts() => _db.getAllContacts();

  // ── Chats ──────────────────────────────────────────────────────────────────

  Future<void> saveChat({
    required int id,
    required String type,
    String? name,
    String? avatarUrl,
    int? peerId,
    String? encryptedKey,
  }) =>
      _db.upsertChat(ChatsCompanion(
        id:           Value(id),
        type:         Value(type),
        name:         Value(name),
        avatarUrl:    Value(avatarUrl),
        peerId:       Value(peerId),
        encryptedKey: Value(encryptedKey),
      ));

  Stream<List<Chat>> watchChats() => _db.watchChats();

  Future<Chat?> getChat(int id) => _db.getChat(id);

  Future<Chat?> getDirectChat(int peerId) => _db.getDirectChat(peerId);

  Future<void> updateLastMessage(int chatId, String text, String at) =>
      _db.updateLastMessage(chatId, text, at);

  Future<void> incrementUnread(int chatId) => _db.incrementUnread(chatId);
  Future<void> clearUnread(int chatId) => _db.clearUnread(chatId);

  // ── Members ────────────────────────────────────────────────────────────────

  Future<void> saveMember(int chatId, int userId, {String role = 'member'}) =>
      _db.upsertMember(ChatMembersCompanion(
        chatId: Value(chatId),
        userId: Value(userId),
        role:   Value(role),
      ));

  Future<List<ChatMember>> getChatMembers(int chatId) =>
      _db.getChatMembers(chatId);

  // ── Messages ───────────────────────────────────────────────────────────────

  Future<void> saveMessage({
    required String id,
    required int chatId,
    required int senderId,
    required String content,
    String mediaType = 'text',
    String? mediaPath,
    required String sentAt,
    String status = 'sent',
    required bool isMe,
  }) =>
      _db.insertMessage(MessagesCompanion(
        id:        Value(id),
        chatId:    Value(chatId),
        senderId:  Value(senderId),
        content:   Value(content),
        mediaType: Value(mediaType),
        mediaPath: Value(mediaPath),
        sentAt:    Value(sentAt),
        status:    Value(status),
        isMe:      Value(isMe),
      ));

  Stream<List<Message>> watchMessages(int chatId) =>
      _db.watchMessages(chatId);

  Future<List<Message>> getMessages(int chatId,
          {int limit = 50, int offset = 0}) =>
      _db.getMessages(chatId, limit: limit, offset: offset);

  Future<void> updateMessageStatus(String id, String status) =>
      _db.updateMessageStatus(id, status);

  Future<void> deleteMessage(String id) => _db.deleteMessage(id);

  Future<void> deleteAllChatMessages(int chatId) =>
      _db.deleteAllChatMessages(chatId);

  Future<void> deleteChatFull(int chatId) => _db.deleteChatFull(chatId);
}
