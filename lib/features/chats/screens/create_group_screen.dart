import 'dart:async';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../../core/constants/app_constants.dart';
import '../../../core/services/chat_service.dart';
import '../../../core/services/local_storage_service.dart';
import '../../../core/theme/app_theme.dart';
import '../../auth/models/user_model.dart';

class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});

  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  // ── Шаг 1: выбор участников ── Шаг 2: имя группы
  int _step = 1;

  // Поиск
  final _searchCtrl = TextEditingController();
  final _nameCtrl   = TextEditingController();
  Timer? _debounce;

  List<UserModel> _searchResults = [];
  final List<UserModel> _selected = [];
  bool _searching  = false;
  bool _creating   = false;
  String? _nameError;

  int _myUserId = 0;

  @override
  void initState() {
    super.initState();
    _loadMyId();
  }

  Future<void> _loadMyId() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() => _myUserId = prefs.getInt(AppConstants.userIdKey) ?? 0);
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    _nameCtrl.dispose();
    _debounce?.cancel();
    super.dispose();
  }

  // ── Поиск ──────────────────────────────────────────────────────────────────

  void _onSearch(String q) {
    _debounce?.cancel();
    if (q.trim().length < 2) {
      setState(() => _searchResults = []);
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 400), () => _search(q.trim()));
  }

  Future<void> _search(String q) async {
    setState(() => _searching = true);
    try {
      final users = await ChatService.searchUsers(q);
      if (!mounted) return;
      // Не показываем себя и уже выбранных
      final filtered = users.where((u) =>
          u.id != _myUserId && !_selected.any((s) => s.id == u.id)).toList();
      setState(() { _searchResults = filtered; _searching = false; });
    } on ChatException catch (e) {
      if (!mounted) return;
      setState(() => _searching = false);
      _showSnack(e.message);
    } catch (_) {
      if (mounted) setState(() => _searching = false);
    }
  }

  void _toggleUser(UserModel user) {
    setState(() {
      if (_selected.any((u) => u.id == user.id)) {
        _selected.removeWhere((u) => u.id == user.id);
      } else {
        if (_selected.length >= 49) {
          _showSnack('Максимум 49 участников');
          return;
        }
        _selected.add(user);
      }
      // Убрать из результатов поиска если выбран
      _searchResults.removeWhere((u) => u.id == user.id);
    });
  }

  // ── Создание группы ────────────────────────────────────────────────────────

  Future<void> _createGroup() async {
    final name = _nameCtrl.text.trim();
    if (name.isEmpty) {
      setState(() => _nameError = 'Введи название группы');
      return;
    }
    if (_selected.isEmpty) {
      _showSnack('Добавь хотя бы одного участника');
      return;
    }
    // Убедимся что myUserId загружен
    if (_myUserId == 0) {
      final prefs = await SharedPreferences.getInstance();
      _myUserId = prefs.getInt(AppConstants.userIdKey) ?? 0;
    }

    setState(() { _creating = true; _nameError = null; });

    try {
      final memberIds = _selected.map((u) => u.id).toList();
      final chatId = await ChatService.createGroupChat(
        name:      name,
        memberIds: memberIds,
      );

      if (!mounted) return;

      // Сохранить чат и участников локально
      final storage = LocalStorageService.instance;
      await storage.saveChat(id: chatId, type: 'group', name: name);
      // Сохраняем себя как admin-участника
      if (_myUserId != 0) {
        await storage.saveMember(chatId, _myUserId, role: 'admin');
      }
      for (final u in _selected) {
        await storage.saveContact(
          id: u.id, username: u.username, displayName: u.displayName,
          avatarUrl: u.avatarUrl, status: u.status, publicKey: u.publicKey,
          lastSeen: u.lastSeen,
        );
        await storage.saveMember(chatId, u.id);
      }

      if (!mounted) return;
      context.go('/chat/$chatId');
    } on ChatException catch (e) {
      if (!mounted) return;
      setState(() => _creating = false);
      _showSnack(e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _creating = false);
      _showSnack('Ошибка: $e');
    }
  }

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  // ── UI ─────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_step == 1 ? 'Добавить участников' : 'Название группы'),
        actions: [
          if (_step == 1 && _selected.isNotEmpty)
            TextButton(
              onPressed: () => setState(() => _step = 2),
              child: const Text('Далее', style: TextStyle(fontWeight: FontWeight.bold)),
            ),
        ],
      ),
      body: _step == 1 ? _buildStep1() : _buildStep2(),
    );
  }

  // Шаг 1 — поиск и выбор участников
  Widget _buildStep1() {
    return Column(
      children: [
        // Выбранные — горизонтальная полоска
        if (_selected.isNotEmpty) _SelectedStrip(
          selected: _selected,
          onRemove: _toggleUser,
        ),

        // Поисковая строка
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: TextField(
            controller: _searchCtrl,
            onChanged: _onSearch,
            decoration: InputDecoration(
              hintText: 'Поиск по username...',
              prefixIcon: const Icon(Icons.search),
              filled: true,
              fillColor: Theme.of(context).brightness == Brightness.dark
                  ? const Color(0xFF252525) : const Color(0xFFF0F0F0),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: BorderSide.none,
              ),
              contentPadding: const EdgeInsets.symmetric(vertical: 0),
            ),
          ),
        ),

        // Результаты
        Expanded(child: _buildSearchResults()),
      ],
    );
  }

  Widget _buildSearchResults() {
    if (_searching) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_searchResults.isEmpty && _searchCtrl.text.trim().length >= 2) {
      return const Center(
          child: Text('Никого не найдено', style: TextStyle(color: Colors.grey)));
    }
    if (_searchResults.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.group_add, size: 64,
                color: AppColors.primary.withOpacity(0.3)),
            const SizedBox(height: 12),
            Text(
              _selected.isEmpty
                  ? 'Найди участников по username'
                  : 'Выбрано: ${_selected.length}',
              style: const TextStyle(color: Colors.grey),
            ),
          ],
        ),
      );
    }
    return ListView.builder(
      itemCount: _searchResults.length,
      itemBuilder: (_, i) {
        final u = _searchResults[i];
        final isSelected = _selected.any((s) => s.id == u.id);
        return ListTile(
          onTap: () => _toggleUser(u),
          leading: _UserAvatar(name: u.displayName, url: u.avatarUrl),
          title: Text(u.displayName,
              style: const TextStyle(fontWeight: FontWeight.w600)),
          subtitle: Text('@${u.username}',
              style: const TextStyle(color: Colors.grey, fontSize: 13)),
          trailing: AnimatedContainer(
            duration: const Duration(milliseconds: 200),
            width: 26, height: 26,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: isSelected ? AppColors.primary : Colors.transparent,
              border: Border.all(
                color: isSelected ? AppColors.primary : Colors.grey,
                width: 2,
              ),
            ),
            child: isSelected
                ? const Icon(Icons.check, size: 16, color: Colors.white)
                : null,
          ),
        );
      },
    );
  }

  // Шаг 2 — название группы
  Widget _buildStep2() {
    return Column(
      children: [
        const SizedBox(height: 24),

        // Иконка группы (placeholder)
        Center(
          child: Stack(
            children: [
              CircleAvatar(
                radius: 44,
                backgroundColor: AppColors.primary.withOpacity(0.15),
                child: Icon(Icons.group, size: 44,
                    color: AppColors.primary),
              ),
              Positioned(
                bottom: 0, right: 0,
                child: CircleAvatar(
                  radius: 14,
                  backgroundColor: AppColors.primary,
                  child: const Icon(Icons.camera_alt, size: 14, color: Colors.white),
                ),
              ),
            ],
          ),
        ),

        const SizedBox(height: 24),

        // Поле имени
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: TextField(
            controller: _nameCtrl,
            autofocus: true,
            maxLength: 64,
            textCapitalization: TextCapitalization.sentences,
            onChanged: (_) => setState(() => _nameError = null),
            decoration: InputDecoration(
              labelText: 'Название группы',
              errorText: _nameError,
              prefixIcon: const Icon(Icons.group_outlined),
              border: const OutlineInputBorder(),
            ),
          ),
        ),

        const SizedBox(height: 8),

        // Список участников
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Text(
            'Участников: ${_selected.length + 1} (включая тебя)',
            style: const TextStyle(color: Colors.grey, fontSize: 13),
          ),
        ),

        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            itemCount: _selected.length,
            itemBuilder: (_, i) => ListTile(
              dense: true,
              leading: _UserAvatar(
                  name: _selected[i].displayName,
                  url:  _selected[i].avatarUrl,
                  radius: 18),
              title: Text(_selected[i].displayName,
                  style: const TextStyle(fontSize: 14)),
              subtitle: Text('@${_selected[i].username}',
                  style: const TextStyle(fontSize: 12, color: Colors.grey)),
              trailing: IconButton(
                icon: const Icon(Icons.close, size: 18),
                onPressed: () => setState(() => _selected.removeAt(i)),
              ),
            ),
          ),
        ),

        // Кнопка создать
        Padding(
          padding: const EdgeInsets.fromLTRB(24, 0, 24, 24),
          child: SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: _creating ? null : _createGroup,
              icon: _creating
                  ? const SizedBox(
                      width: 18, height: 18,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: Colors.white))
                  : const Icon(Icons.check),
              label: const Text('Создать группу',
                  style: TextStyle(fontSize: 16)),
            ),
          ),
        ),
      ],
    );
  }
}

// ── Горизонтальная полоска выбранных участников ────────────────────────────────

class _SelectedStrip extends StatelessWidget {
  final List<UserModel> selected;
  final ValueChanged<UserModel> onRemove;
  const _SelectedStrip({required this.selected, required this.onRemove});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 88,
      color: Theme.of(context).brightness == Brightness.dark
          ? const Color(0xFF1E1E1E) : const Color(0xFFF8F8F8),
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        itemCount: selected.length,
        itemBuilder: (_, i) {
          final u = selected[i];
          return Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Column(
              children: [
                Stack(
                  children: [
                    _UserAvatar(name: u.displayName, url: u.avatarUrl, radius: 24),
                    Positioned(
                      top: -2, right: -2,
                      child: GestureDetector(
                        onTap: () => onRemove(u),
                        child: CircleAvatar(
                          radius: 9,
                          backgroundColor:
                              Theme.of(context).scaffoldBackgroundColor,
                          child: const Icon(Icons.close, size: 12,
                              color: Colors.grey),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                SizedBox(
                  width: 52,
                  child: Text(
                    u.displayName.split(' ').first,
                    textAlign: TextAlign.center,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 11),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }
}

class _UserAvatar extends StatelessWidget {
  final String name;
  final String? url;
  final double radius;
  const _UserAvatar({required this.name, this.url, this.radius = 22});

  @override
  Widget build(BuildContext context) {
    const colors = [
      Color(0xFF6C63FF), Color(0xFF03DAC6), Color(0xFFFF6584),
      Color(0xFFFFB347), Color(0xFF57CC99), Color(0xFF4FC3F7),
    ];
    final color = name.isNotEmpty
        ? colors[name.codeUnitAt(0) % colors.length]
        : colors[0];
    return CircleAvatar(
      radius: radius,
      backgroundColor: color,
      backgroundImage: url != null ? NetworkImage(url!) : null,
      child: url == null
          ? Text(name.isNotEmpty ? name[0].toUpperCase() : '?',
              style: TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                  fontSize: radius * 0.8))
          : null,
    );
  }
}
