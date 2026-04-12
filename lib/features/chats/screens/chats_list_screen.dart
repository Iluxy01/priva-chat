import 'dart:async';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../../core/constants/app_constants.dart';
import '../../../core/database/app_database.dart';
import '../../../core/services/chat_service.dart';
import '../../../core/services/local_storage_service.dart';
import '../../../core/services/websocket_service.dart';
import '../../../core/widgets/connection_status_bar.dart';
import '../widgets/chat_tile.dart';

class ChatsListScreen extends StatefulWidget {
  const ChatsListScreen({super.key});
  @override
  State<ChatsListScreen> createState() => _ChatsListScreenState();
}

class _ChatsListScreenState extends State<ChatsListScreen> {
  int _myUserId = 0;
  bool _syncing = false;
  int? _activeChatId;

  // Ключ SharedPreferences для хранения удалённых чатов
  static const _deletedChatsKey = 'deleted_chat_ids';

  late final StreamSubscription _incomingSub;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final prefs = await SharedPreferences.getInstance();
    if (mounted) setState(() => _myUserId = prefs.getInt(AppConstants.userIdKey) ?? 0);

    WebSocketService.instance.addListener(_onWsChanged);

    // Глобальный слушатель входящих:
    // 1) Сохраняет само сообщение (чтобы оно появилось когда откроешь чат)
    // 2) Создаёт чат локально если его ещё нет
    // 3) Обновляет счётчик непрочитанных
    _incomingSub = WebSocketService.instance.onMessage.listen((msg) async {
      // Убедиться что чат существует локально (fix: первое сообщение)
      await _ensureChatExists(msg);

      // Сохраняем сообщение в БД (fix: сообщение не появлялось при входе в чат)
      final existingMsg = await LocalStorageService.instance
          .getMessages(msg.chatId, limit: 1000)
          .then((list) => list.any((m) => m.id == (msg.tempId ?? '')));
      if (!existingMsg && msg.tempId != null) {
        await LocalStorageService.instance.saveMessage(
          id: msg.tempId!,
          chatId: msg.chatId,
          senderId: msg.senderId,
          content: msg.encryptedContent,
          mediaType: msg.mediaType,
          sentAt: msg.sentAt,
          status: 'delivered',
          isMe: false,
        );
      }

      await LocalStorageService.instance.updateLastMessage(
          msg.chatId, msg.encryptedContent, msg.sentAt);

      // Не считаем unread если чат открыт
      if (msg.chatId != _activeChatId) {
        await LocalStorageService.instance.incrementUnread(msg.chatId);
      }
    });

    await WebSocketService.instance.connect();
    await _syncChats();
  }

  /// Создаёт чат локально если его нет — нужно когда приходит ПЕРВОЕ сообщение
  Future<void> _ensureChatExists(WsMessage msg) async {
    final existing = await LocalStorageService.instance.getChat(msg.chatId);
    if (existing != null) return;

    // Чата нет — создаём из данных которые есть
    // Тип пока неизвестен, ставим direct и обновим при следующей синхронизации
    await LocalStorageService.instance.saveChat(
      id: msg.chatId,
      type: 'direct',
      peerId: msg.senderId,
    );
    await LocalStorageService.instance.saveMember(msg.chatId, msg.senderId);
    await LocalStorageService.instance.saveMember(msg.chatId, _myUserId);

    // Подгружаем реальные данные с сервера в фоне
    _syncSingleChat(msg.chatId);
  }

  /// Синхронизирует один конкретный чат с сервера
  Future<void> _syncSingleChat(int chatId) async {
    try {
      final serverChats = await ChatService.getChats();
      final sc = serverChats.where((c) => c.id == chatId).firstOrNull;
      if (sc == null) return;
      int? peerId;
      if (sc.type == 'direct') {
        peerId = sc.members
            .where((m) => m.id != _myUserId)
            .map((m) => m.id)
            .firstOrNull;
      }
      await LocalStorageService.instance.saveChat(
        id: sc.id, type: sc.type,
        name: sc.name, avatarUrl: sc.avatarUrl, peerId: peerId,
      );
      for (final member in sc.members) {
        await LocalStorageService.instance.saveContact(
          id: member.id, username: member.username,
          displayName: member.displayName, avatarUrl: member.avatarUrl,
          publicKey: member.publicKey, lastSeen: member.lastSeen,
        );
        await LocalStorageService.instance.saveMember(sc.id, member.id);
      }
    } catch (e) {
      debugPrint('[ChatsListScreen] syncSingleChat error: $e');
    }
  }

  void _onWsChanged() {
    if (mounted) setState(() {});
  }

  /// Возвращает список id чатов которые пользователь удалил
  Future<Set<int>> _getDeletedChatIds() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_deletedChatsKey) ?? [];
    return raw.map(int.parse).toSet();
  }

  /// Добавляет id в список удалённых
  Future<void> _markChatDeleted(int chatId) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_deletedChatsKey) ?? [];
    if (!raw.contains(chatId.toString())) {
      raw.add(chatId.toString());
      await prefs.setStringList(_deletedChatsKey, raw);
    }
  }

  Future<void> _syncChats() async {
    if (_syncing) return;
    if (mounted) setState(() => _syncing = true);
    try {
      final serverChats = await ChatService.getChats();
      // FIX: получаем список удалённых чатов — их не восстанавливаем
      final deletedIds = await _getDeletedChatIds();

      for (final sc in serverChats) {
        // Пропускаем чаты которые пользователь удалил локально
        if (deletedIds.contains(sc.id)) continue;

        int? peerId;
        if (sc.type == 'direct') {
          peerId = sc.members
              .where((m) => m.id != _myUserId)
              .map((m) => m.id)
              .firstOrNull;
        }
        await LocalStorageService.instance.saveChat(
          id: sc.id, type: sc.type,
          name: sc.name, avatarUrl: sc.avatarUrl, peerId: peerId,
        );
        for (final member in sc.members) {
          await LocalStorageService.instance.saveContact(
            id: member.id, username: member.username,
            displayName: member.displayName, avatarUrl: member.avatarUrl,
            publicKey: member.publicKey, lastSeen: member.lastSeen,
          );
          await LocalStorageService.instance.saveMember(sc.id, member.id);
        }
      }
    } catch (e) {
      debugPrint('[ChatsListScreen] sync error: $e');
    } finally {
      if (mounted) setState(() => _syncing = false);
    }
  }

  Future<void> _confirmDeleteChat(BuildContext context, Chat chat) async {
    final name = chat.type == 'group'
        ? (chat.name ?? 'группа')
        : 'чат';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text('Удалить $name?'),
        content: Text(
          chat.type == 'group'
              ? 'Все сообщения группы будут удалены с устройства. '
                'Другие участники не потеряют свою историю.'
              : 'Все сообщения будут удалены с этого устройства. '
                'Собеседник не потеряет свои сообщения.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Отмена'),
          ),
          TextButton(
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Удалить'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    // FIX: сначала запоминаем что удалили, потом удаляем
    await _markChatDeleted(chat.id);
    await ChatService.deleteChat(chat.id);
    await LocalStorageService.instance.deleteChatFull(chat.id);
  }

  @override
  void dispose() {
    _incomingSub.cancel();
    WebSocketService.instance.removeListener(_onWsChanged);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('PrivaChat',
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 22)),
        automaticallyImplyLeading: false,
        actions: [
          if (_syncing)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 8),
              child: Center(
                child: SizedBox(
                  width: 18, height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                ),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.search_rounded),
            tooltip: 'Найти пользователя',
            onPressed: () => context.push('/search'),
          ),
          IconButton(
            icon: const Icon(Icons.person_outline_rounded),
            tooltip: 'Профиль',
            onPressed: () => context.push('/profile'),
          ),
        ],
      ),
      body: Column(
        children: [
          const ConnectionStatusBar(),
          Expanded(child: _buildChatList()),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () async {
          await context.push('/create-group');
          await _syncChats();
        },
        tooltip: 'Создать группу',
        child: const Icon(Icons.group_add_rounded),
      ),
    );
  }

  Widget _buildChatList() {
    return StreamBuilder<List<Chat>>(
      stream: LocalStorageService.instance.watchChats(),
      builder: (context, snap) {
        if (snap.connectionState == ConnectionState.waiting && !snap.hasData) {
          return const Center(child: CircularProgressIndicator());
        }
        final chats = snap.data ?? [];
        if (chats.isEmpty) {
          return _EmptyState(onSearch: () => context.push('/search'));
        }
        return RefreshIndicator(
          onRefresh: _syncChats,
          child: ListView.separated(
            itemCount: chats.length,
            separatorBuilder: (_, __) =>
                const Divider(height: 1, indent: 76, endIndent: 16),
            itemBuilder: (context, i) {
              final chat = chats[i];
              return Dismissible(
                key: ValueKey(chat.id),
                direction: DismissDirection.endToStart,
                confirmDismiss: (_) async {
                  await _confirmDeleteChat(context, chat);
                  return false;
                },
                background: Container(
                  alignment: Alignment.centerRight,
                  color: Colors.red,
                  padding: const EdgeInsets.only(right: 20),
                  child: const Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.delete_outline, color: Colors.white, size: 28),
                      SizedBox(height: 4),
                      Text('Удалить',
                          style: TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                              fontWeight: FontWeight.w600)),
                    ],
                  ),
                ),
                child: ChatTile(
                  chat: chat,
                  myUserId: _myUserId,
                  onTap: () async {
                    _activeChatId = chat.id;
                    await context.push('/chat/${chat.id}');
                    _activeChatId = null;
                    await LocalStorageService.instance.clearUnread(chat.id);
                  },
                ),
              );
            },
          ),
        );
      },
    );
  }
}

class _EmptyState extends StatelessWidget {
  final VoidCallback onSearch;
  const _EmptyState({required this.onSearch});

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(context).colorScheme.primary;
    return Center(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.chat_bubble_outline_rounded,
                size: 80, color: color.withOpacity(0.35)),
            const SizedBox(height: 20),
            const Text('Нет чатов',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)),
            const SizedBox(height: 10),
            const Text(
              'Найди друга по имени пользователя\nи начни переписку',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 14, color: Colors.grey),
            ),
            const SizedBox(height: 28),
            FilledButton.icon(
              onPressed: onSearch,
              icon: const Icon(Icons.search_rounded),
              label: const Text('Найти пользователя'),
            ),
          ],
        ),
      ),
    );
  }
}
