import 'dart:async';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../../../core/constants/app_constants.dart';
import '../../../core/services/chat_service.dart';
import '../../../core/services/key_exchange_service.dart';
import '../../../core/services/local_storage_service.dart';
import '../../../core/theme/app_theme.dart';
import '../../auth/models/user_model.dart';

class UserSearchScreen extends StatefulWidget {
  const UserSearchScreen({super.key});

  @override
  State<UserSearchScreen> createState() => _UserSearchScreenState();
}

class _UserSearchScreenState extends State<UserSearchScreen> {
  final _ctrl  = TextEditingController();
  final _focus = FocusNode();

  List<UserModel> _results = [];
  bool   _loading = false;
  String? _error;
  Timer? _debounce;

  @override
  void initState() {
    super.initState();
    _focus.requestFocus();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _focus.dispose();
    _debounce?.cancel();
    super.dispose();
  }

  void _onChanged(String q) {
    _debounce?.cancel();
    if (q.trim().length < 2) {
      setState(() { _results = []; _error = null; });
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 400), () => _search(q.trim()));
  }

  Future<void> _search(String q) async {
    setState(() { _loading = true; _error = null; });
    try {
      final users = await ChatService.searchUsers(q);
      if (!mounted) return;
      setState(() { _results = users; _loading = false; });
    } on ChatException catch (e) {
      // Показываем точное сообщение от сервера
      if (!mounted) return;
      setState(() { _error = e.message; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      setState(() { _error = 'Ошибка: $e'; _loading = false; });
    }
  }

  Future<void> _openChat(UserModel user) async {
    await LocalStorageService.instance.saveContact(
      id:          user.id,
      username:    user.username,
      displayName: user.displayName,
      avatarUrl:   user.avatarUrl,
      status:      user.status,
      publicKey:   user.publicKey,
      lastSeen:    user.lastSeen,
    );

    if (!mounted) return;

    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => const Center(child: CircularProgressIndicator()),
    );

    try {
      final chatId = await ChatService.createDirectChat(user.id);
      if (!mounted) return;
      context.pop(); // закрыть индикатор

      // Сохраняем чат локально
      await LocalStorageService.instance.saveChat(
        id:     chatId,
        type:   'direct',
        peerId: user.id,
      );
      // Сохраняем обоих участников — собеседника и себя
      // (myUserId нужен чтобы _memberIds в ChatScreen не был пустым)
      await LocalStorageService.instance.saveMember(chatId, user.id);
      // Получаем своё id из SharedPreferences
      final prefs = await SharedPreferences.getInstance();
      final myId = prefs.getInt(AppConstants.userIdKey) ?? 0;
      if (myId != 0) {
        await LocalStorageService.instance.saveMember(chatId, myId);
      }

      // Инициализируем E2E ключ сразу при создании чата.
      // Если у собеседника ещё нет public_key — ensureChatKey ничего не отправит,
      // KeyExchangeService позаботится о переотправке при появлении ключа.
      if (user.publicKey != null && user.publicKey!.isNotEmpty) {
        await KeyExchangeService.instance.ensureChatKey(
          chatId: chatId,
          memberUserIds: [user.id],
        );
      }

      if (!mounted) return;
      context.go('/chat/$chatId');
    } on ChatException catch (e) {
      if (!mounted) return;
      context.pop();
      _showSnack(e.message, isError: true);
    } catch (e) {
      if (!mounted) return;
      context.pop();
      _showSnack('Ошибка: $e', isError: true);
    }
  }

  void _showSnack(String msg, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        backgroundColor: isError ? Colors.red : null,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: TextField(
          controller:       _ctrl,
          focusNode:        _focus,
          onChanged:        _onChanged,
          textInputAction:  TextInputAction.search,
          decoration: const InputDecoration(
            hintText: 'Поиск по username...',
            border:   InputBorder.none,
            contentPadding: EdgeInsets.symmetric(horizontal: 8),
          ),
          style: const TextStyle(fontSize: 16),
        ),
        actions: [
          if (_ctrl.text.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.clear),
              onPressed: () {
                _ctrl.clear();
                setState(() { _results = []; _error = null; });
              },
            ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.error_outline, size: 48, color: Colors.red),
              const SizedBox(height: 12),
              Text(
                _error!,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.red, fontSize: 15),
              ),
              const SizedBox(height: 16),
              TextButton.icon(
                onPressed: () => _search(_ctrl.text.trim()),
                icon: const Icon(Icons.refresh),
                label: const Text('Повторить'),
              ),
            ],
          ),
        ),
      );
    }

    if (_ctrl.text.trim().length < 2) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.person_search, size: 72,
                color: AppColors.primary.withOpacity(0.3)),
            const SizedBox(height: 16),
            const Text('Введите минимум 2 символа',
                style: TextStyle(color: Colors.grey, fontSize: 15)),
          ],
        ),
      );
    }

    if (_results.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.search_off, size: 48, color: Colors.grey),
            const SizedBox(height: 12),
            Text('Никого не найдено по "${_ctrl.text}"',
                style: const TextStyle(color: Colors.grey)),
          ],
        ),
      );
    }

    return ListView.builder(
      itemCount: _results.length,
      itemBuilder: (context, i) => _UserTile(
        user:  _results[i],
        onTap: () => _openChat(_results[i]),
      ),
    );
  }
}

class _UserTile extends StatelessWidget {
  final UserModel user;
  final VoidCallback onTap;
  const _UserTile({required this.user, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return ListTile(
      onTap: onTap,
      leading: CircleAvatar(
        backgroundColor: const Color(0xFF6C63FF),
        backgroundImage: user.avatarUrl != null ? NetworkImage(user.avatarUrl!) : null,
        child: user.avatarUrl == null
            ? Text(user.displayName[0].toUpperCase(),
                style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold))
            : null,
      ),
      title: Text(user.displayName,
          style: const TextStyle(fontWeight: FontWeight.w600)),
      subtitle: Text('@${user.username}',
          style: const TextStyle(color: Colors.grey)),
      trailing: const Icon(Icons.chevron_right),
    );
  }
}
