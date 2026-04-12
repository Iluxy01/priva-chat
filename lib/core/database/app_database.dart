import 'package:drift/drift.dart';
import 'package:drift_flutter/drift_flutter.dart';
import 'package:path_provider/path_provider.dart';

part 'app_database.g.dart';

// ═══════════════════════════════════════════════════════════════
//  ТАБЛИЦЫ
// ═══════════════════════════════════════════════════════════════

// Контакты / пользователи которых мы знаем
class Contacts extends Table {
  IntColumn get id          => integer()();
  TextColumn get username   => text()();
  TextColumn get displayName=> text()();
  TextColumn get avatarUrl  => text().nullable()();
  TextColumn get status     => text().nullable()();
  TextColumn get publicKey  => text().nullable()();
  TextColumn get lastSeen   => text().nullable()();

  @override
  Set<Column> get primaryKey => {id};
}

// Чаты (личные и групповые)
class Chats extends Table {
  IntColumn  get id          => integer()();
  TextColumn get type        => text()(); // 'direct' | 'group'
  TextColumn get name        => text().nullable()();
  TextColumn get avatarUrl   => text().nullable()();
  // Для direct: id собеседника
  IntColumn  get peerId      => integer().nullable()();
  // Последнее сообщение (для превью)
  TextColumn get lastMessage => text().nullable()();
  TextColumn get lastMessageAt => text().nullable()();
  IntColumn  get unreadCount => integer().withDefault(const Constant(0))();
  TextColumn get encryptedKey=> text().nullable()(); // зашифрованный ключ чата

  @override
  Set<Column> get primaryKey => {id};
}

// Участники чата
class ChatMembers extends Table {
  IntColumn get chatId  => integer().references(Chats, #id)();
  IntColumn get userId  => integer()();
  TextColumn get role   => text().withDefault(const Constant('member'))();

  @override
  Set<Column> get primaryKey => {chatId, userId};
}

// Сообщения — хранятся ТОЛЬКО локально, никогда не уходят на сервер в виде plaintext
class Messages extends Table {
  TextColumn get id            => text()(); // UUID генерируем локально
  IntColumn  get chatId        => integer().references(Chats, #id)();
  IntColumn  get senderId      => integer()();
  TextColumn get content       => text()(); // plaintext (расшифрованный)
  TextColumn get mediaType     => text().withDefault(const Constant('text'))(); // text|image|video|file
  TextColumn get mediaPath     => text().nullable()(); // локальный путь к файлу
  TextColumn get sentAt        => text()(); // ISO8601
  TextColumn get status        => text().withDefault(const Constant('sending'))(); // sending|sent|delivered|read
  BoolColumn get isMe          => boolean().withDefault(const Constant(false))();

  @override
  Set<Column> get primaryKey => {id};
}

// ═══════════════════════════════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════════════════════════════

@DriftDatabase(tables: [Contacts, Chats, ChatMembers, Messages])
class AppDatabase extends _$AppDatabase {
  AppDatabase() : super(_openConnection());

  @override
  int get schemaVersion => 1;

  // ── Contacts ──────────────────────────────────────────────────

  Future<void> upsertContact(ContactsCompanion c) =>
      into(contacts).insertOnConflictUpdate(c);

  Future<Contact?> getContact(int id) =>
      (select(contacts)..where((t) => t.id.equals(id))).getSingleOrNull();

  Future<List<Contact>> getAllContacts() => select(contacts).get();

  // ── Chats ─────────────────────────────────────────────────────

  Future<void> upsertChat(ChatsCompanion c) =>
      into(chats).insertOnConflictUpdate(c);

  Stream<List<Chat>> watchChats() =>
      (select(chats)
            ..orderBy([(t) => OrderingTerm.desc(t.lastMessageAt)]))
          .watch();

  Future<Chat?> getChat(int id) =>
      (select(chats)..where((t) => t.id.equals(id))).getSingleOrNull();

  Future<Chat?> getDirectChat(int peerId) =>
      (select(chats)
            ..where((t) =>
                t.type.equals('direct') & t.peerId.equals(peerId)))
          .getSingleOrNull();

  Future<void> updateLastMessage(
      int chatId, String text, String at) async {
    await (update(chats)..where((t) => t.id.equals(chatId))).write(
      ChatsCompanion(
        lastMessage: Value(text),
        lastMessageAt: Value(at),
      ),
    );
  }

  Future<void> incrementUnread(int chatId) async {
    final chat = await getChat(chatId);
    if (chat == null) return;
    await (update(chats)..where((t) => t.id.equals(chatId))).write(
      ChatsCompanion(unreadCount: Value(chat.unreadCount + 1)),
    );
  }

  Future<void> clearUnread(int chatId) async {
    await (update(chats)..where((t) => t.id.equals(chatId))).write(
      const ChatsCompanion(unreadCount: Value(0)),
    );
  }

  // ── Chat Members ──────────────────────────────────────────────

  Future<void> upsertMember(ChatMembersCompanion m) =>
      into(chatMembers).insertOnConflictUpdate(m);

  Future<List<ChatMember>> getChatMembers(int chatId) =>
      (select(chatMembers)..where((t) => t.chatId.equals(chatId))).get();

  // ── Messages ──────────────────────────────────────────────────

  Stream<List<Message>> watchMessages(int chatId) =>
      (select(messages)
            ..where((t) => t.chatId.equals(chatId))
            ..orderBy([(t) => OrderingTerm.asc(t.sentAt)]))
          .watch();

  Future<void> insertMessage(MessagesCompanion m) =>
      into(messages).insertOnConflictUpdate(m);

  Future<void> updateMessageStatus(String id, String status) =>
      (update(messages)..where((t) => t.id.equals(id))).write(
        MessagesCompanion(status: Value(status)),
      );

  Future<List<Message>> getMessages(int chatId, {int limit = 50, int offset = 0}) =>
      (select(messages)
            ..where((t) => t.chatId.equals(chatId))
            ..orderBy([(t) => OrderingTerm.desc(t.sentAt)])
            ..limit(limit, offset: offset))
          .get();

  Future<void> deleteMessage(String id) =>
      (delete(messages)..where((t) => t.id.equals(id))).go();

  Future<void> deleteAllChatMessages(int chatId) =>
      (delete(messages)..where((t) => t.chatId.equals(chatId))).go();

  // ── Delete Chat (cascade) ─────────────────────────────────────

  Future<void> deleteChatFull(int chatId) async {
    await (delete(messages)..where((t) => t.chatId.equals(chatId))).go();
    await (delete(chatMembers)..where((t) => t.chatId.equals(chatId))).go();
    await (delete(chats)..where((t) => t.id.equals(chatId))).go();
  }
}

// ── Открытие БД ───────────────────────────────────────────────

QueryExecutor _openConnection() {
  return driftDatabase(
    name: 'privachat',
    native: DriftNativeOptions(
      databaseDirectory: getApplicationDocumentsDirectory,
    ),
  );
}
