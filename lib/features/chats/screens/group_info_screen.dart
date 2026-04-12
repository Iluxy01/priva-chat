import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../../core/constants/app_constants.dart';
import '../../../core/database/app_database.dart';
import '../../../core/services/local_storage_service.dart';
import '../../../core/services/chat_service.dart';
import '../../../core/theme/app_theme.dart';
import '../../auth/models/user_model.dart';

// Ключ для хранения удалённых чатов (совпадает с ChatsListScreen и ChatScreen)
const _deletedChatsKeyGroup = 'deleted_chat_ids';

class GroupInfoScreen extends StatefulWidget {
  final int chatId;
  const GroupInfoScreen({super.key, required this.chatId});

  @override
  State<GroupInfoScreen> createState() => _GroupInfoScreenState();
}

class _GroupInfoScreenState extends State<GroupInfoScreen> {
  Chat? _chat;
  List<_MemberInfo> _members = [];
  int _myUserId = 0;
  bool _amAdmin = false;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    _myUserId = prefs.getInt(AppConstants.userIdKey) ?? 0;

    final chat = await LocalStorageService.instance.getChat(widget.chatId);
    final localMembers = await LocalStorageService.instance.getChatMembers(widget.chatId);

    final infos = <_MemberInfo>[];
    for (final m in localMembers) {
      final contact = await LocalStorageService.instance.getContact(m.userId);
      infos.add(_MemberInfo(
        userId: m.userId,
        role:   m.role,
        displayName: contact?.displayName ?? contact?.username ?? 'Пользователь',
        username:    contact?.username ?? '',
        avatarUrl:   contact?.avatarUrl,
      ));
    }

    // Admins first, then alphabetical
    infos.sort((a, b) {
      if (a.role == 'admin' && b.role != 'admin') return -1;
      if (b.role == 'admin' && a.role != 'admin') return 1;
      return a.displayName.compareTo(b.displayName);
    });

    if (!mounted) return;
    setState(() {
      _chat    = chat;
      _members = infos;
      _amAdmin = infos.any((m) => m.userId == _myUserId && m.role == 'admin');
      _loading = false;
    });
  }

  Future<void> _deleteOrLeave() async {
    final action = _amAdmin ? 'Удалить группу' : 'Покинуть группу';
    final body = _amAdmin
        ? 'Группа будет удалена для всех участников. Сообщения на устройствах участников останутся.'
        : 'Ты покинешь группу. Твои сообщения на твоём устройстве останутся.';

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: Text(action),
        content: Text(body),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Отмена'),
          ),
          TextButton(
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            onPressed: () => Navigator.pop(context, true),
            child: Text(action),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    // FIX: запоминаем что удалили — чтобы не восстановилось при следующей синхронизации
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_deletedChatsKeyGroup) ?? [];
    if (!raw.contains(widget.chatId.toString())) {
      raw.add(widget.chatId.toString());
      await prefs.setStringList(_deletedChatsKeyGroup, raw);
    }

    await ChatService.deleteChat(widget.chatId);
    await LocalStorageService.instance.deleteChatFull(widget.chatId);
    if (mounted) context.go('/chats');
  }

  Future<void> _addMember(UserModel user) async {
    try {
      await ChatService.addMemberToGroup(widget.chatId, user.id);
      await LocalStorageService.instance.saveContact(
        id: user.id, username: user.username,
        displayName: user.displayName, avatarUrl: user.avatarUrl,
        status: user.status, publicKey: user.publicKey, lastSeen: user.lastSeen,
      );
      await LocalStorageService.instance.saveMember(widget.chatId, user.id);
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${user.displayName} добавлен')));
      }
    } on ChatException catch (e) {
      if (mounted) ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Scaffold(body: Center(child: CircularProgressIndicator()));

    final name = _chat?.name ?? 'Группа';

    return Scaffold(
      appBar: AppBar(
        // FIX: явная кнопка назад
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () {
            if (context.canPop()) {
              context.pop();
            } else {
              context.go('/chats');
            }
          },
        ),
        title: Text(name),
        actions: [
          PopupMenuButton<String>(
            onSelected: (v) {
              if (v == 'delete') _deleteOrLeave();
            },
            itemBuilder: (_) => [
              PopupMenuItem(
                value: 'delete',
                child: Row(children: [
                  Icon(
                    _amAdmin ? Icons.delete_outline : Icons.exit_to_app,
                    color: Colors.red,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _amAdmin ? 'Удалить группу' : 'Покинуть группу',
                    style: const TextStyle(color: Colors.red),
                  ),
                ]),
              ),
            ],
          ),
        ],
      ),
      body: ListView(
        children: [
          // Шапка группы
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 24),
            child: Column(
              children: [
                CircleAvatar(
                  radius: 44,
                  backgroundColor: AppColors.primary.withOpacity(0.15),
                  child: Icon(Icons.group, size: 44, color: AppColors.primary),
                ),
                const SizedBox(height: 12),
                Text(name,
                    style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text('${_members.length} участников',
                    style: const TextStyle(color: Colors.grey)),
              ],
            ),
          ),

          const Divider(height: 1),

          // Заголовок участников
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
            child: Row(
              children: [
                const Expanded(
                  child: Text('УЧАСТНИКИ',
                      style: TextStyle(fontSize: 12, color: Colors.grey,
                          fontWeight: FontWeight.w600, letterSpacing: 0.8)),
                ),
                if (_amAdmin)
                  TextButton.icon(
                    onPressed: _showAddMemberDialog,
                    icon: const Icon(Icons.person_add_outlined, size: 18),
                    label: const Text('Добавить'),
                    style: TextButton.styleFrom(
                        padding: const EdgeInsets.symmetric(horizontal: 8)),
                  ),
              ],
            ),
          ),

          // Список участников
          ..._members.map((m) => _MemberTile(
                info:     m,
                isMe:     m.userId == _myUserId,
                amAdmin:  _amAdmin,
              )),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Future<void> _showAddMemberDialog() async {
    await showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => _AddMemberSheet(
        existingIds: _members.map((m) => m.userId).toSet(),
        onAdd: _addMember,
      ),
    );
  }
}

// ── Строка участника ──────────────────────────────────────────────────────────

class _MemberTile extends StatelessWidget {
  final _MemberInfo info;
  final bool isMe;
  final bool amAdmin;
  const _MemberTile({required this.info, required this.isMe, required this.amAdmin});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: _SmallAvatar(name: info.displayName, url: info.avatarUrl),
      title: Row(
        children: [
          Text(info.displayName,
              style: const TextStyle(fontWeight: FontWeight.w600)),
          if (isMe) ...[
            const SizedBox(width: 6),
            const Text('(ты)',
                style: TextStyle(color: Colors.grey, fontSize: 13)),
          ],
        ],
      ),
      subtitle: Text('@${info.username}',
          style: const TextStyle(color: Colors.grey, fontSize: 13)),
      trailing: info.role == 'admin'
          ? Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: AppColors.primary.withOpacity(0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Text('admin',
                  style: TextStyle(
                      color: AppColors.primary,
                      fontSize: 12,
                      fontWeight: FontWeight.w600)),
            )
          : null,
    );
  }
}

// ── Боттом-шит добавления участника ──────────────────────────────────────────

class _AddMemberSheet extends StatefulWidget {
  final Set<int> existingIds;
  final Future<void> Function(UserModel) onAdd;
  const _AddMemberSheet({required this.existingIds, required this.onAdd});

  @override
  State<_AddMemberSheet> createState() => _AddMemberSheetState();
}

class _AddMemberSheetState extends State<_AddMemberSheet> {
  final _ctrl = TextEditingController();
  List<UserModel> _results = [];
  bool _loading = false;
  bool _adding  = false;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _search(String q) async {
    if (q.trim().length < 2) { setState(() => _results = []); return; }
    setState(() => _loading = true);
    try {
      final users = await ChatService.searchUsers(q.trim());
      if (!mounted) return;
      setState(() {
        _results = users.where((u) => !widget.existingIds.contains(u.id)).toList();
        _loading = false;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final bottom = MediaQuery.of(context).viewInsets.bottom;
    return Container(
      height: 420 + bottom,
      decoration: BoxDecoration(
        color: Theme.of(context).scaffoldBackgroundColor,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(20)),
      ),
      padding: EdgeInsets.only(bottom: bottom),
      child: Column(
        children: [
          const SizedBox(height: 8),
          Container(width: 36, height: 4,
              decoration: BoxDecoration(color: Colors.grey[300],
                  borderRadius: BorderRadius.circular(2))),
          const SizedBox(height: 12),
          const Text('Добавить участника',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: TextField(
              controller: _ctrl,
              autofocus: true,
              onChanged: _search,
              decoration: const InputDecoration(
                hintText: 'Поиск по username...',
                prefixIcon: Icon(Icons.search),
                border: OutlineInputBorder(),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : ListView.builder(
                    itemCount: _results.length,
                    itemBuilder: (_, i) {
                      final u = _results[i];
                      return ListTile(
                        leading: _SmallAvatar(name: u.displayName, url: u.avatarUrl),
                        title: Text(u.displayName),
                        subtitle: Text('@${u.username}'),
                        trailing: _adding
                            ? const SizedBox(width: 20, height: 20,
                                child: CircularProgressIndicator(strokeWidth: 2))
                            : const Icon(Icons.person_add_outlined),
                        onTap: () async {
                          setState(() => _adding = true);
                          await widget.onAdd(u);
                          if (mounted) context.pop();
                        },
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

class _MemberInfo {
  final int userId;
  final String role;
  final String displayName;
  final String username;
  final String? avatarUrl;
  const _MemberInfo({
    required this.userId, required this.role,
    required this.displayName, required this.username, this.avatarUrl,
  });
}

class _SmallAvatar extends StatelessWidget {
  final String name;
  final String? url;
  const _SmallAvatar({required this.name, this.url});

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: 22,
      backgroundColor: const Color(0xFF6C63FF),
      backgroundImage: url != null ? NetworkImage(url!) : null,
      child: url == null
          ? Text(name.isNotEmpty ? name[0].toUpperCase() : '?',
              style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold))
          : null,
    );
  }
}
