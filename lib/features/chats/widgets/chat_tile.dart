import 'package:flutter/material.dart';
import 'package:timeago/timeago.dart' as timeago;
import '../../../core/database/app_database.dart';
import '../../../core/services/local_storage_service.dart';
import '../../../core/widgets/connection_status_bar.dart';

class ChatTile extends StatelessWidget {
  final Chat chat;
  final int myUserId;
  final VoidCallback onTap;

  const ChatTile({
    super.key,
    required this.chat,
    required this.myUserId,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Contact?>(
      future: _getPeer(),
      builder: (context, snap) {
        final peer = snap.data;
        final name = chat.type == 'direct'
            ? (peer?.displayName ?? peer?.username ?? '...')
            : (chat.name ?? 'Группа');
        final avatarUrl = chat.type == 'direct' ? peer?.avatarUrl : chat.avatarUrl;
        final peerId = chat.peerId;

        return ListTile(
          onTap: onTap,
          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
          leading: Stack(
            clipBehavior: Clip.none,
            children: [
              _Avatar(name: name, url: avatarUrl),
              if (chat.type == 'direct' && peerId != null)
                Positioned(
                  bottom: -2,
                  right: -2,
                  child: OnlineIndicator(userId: peerId, size: 13),
                ),
            ],
          ),
          title: Text(
            name,
            style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 15),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          subtitle: chat.lastMessage != null
              ? Text(
                  chat.lastMessage!,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 13),
                )
              : const Text('Нет сообщений',
                  style: TextStyle(fontSize: 13, color: Colors.grey)),
          trailing: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              if (chat.lastMessageAt != null)
                Text(
                  _fmtTime(chat.lastMessageAt!),
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              if (chat.unreadCount > 0) ...[
                const SizedBox(height: 4),
                _UnreadBadge(count: chat.unreadCount),
              ],
            ],
          ),
        );
      },
    );
  }

  Future<Contact?> _getPeer() async {
    if (chat.type != 'direct' || chat.peerId == null) return null;
    return LocalStorageService.instance.getContact(chat.peerId!);
  }

  String _fmtTime(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      final now = DateTime.now();
      if (now.difference(dt).inHours < 24) {
        return '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
      }
      return timeago.format(dt, locale: 'ru');
    } catch (_) {
      return '';
    }
  }
}

class _Avatar extends StatelessWidget {
  final String name;
  final String? url;
  const _Avatar({required this.name, this.url});

  @override
  Widget build(BuildContext context) {
    return CircleAvatar(
      radius: 26,
      backgroundColor: _colorFor(name),
      backgroundImage: url != null ? NetworkImage(url!) : null,
      child: url == null
          ? Text(
              name.isNotEmpty ? name[0].toUpperCase() : '?',
              style: const TextStyle(
                  color: Colors.white, fontWeight: FontWeight.bold, fontSize: 18),
            )
          : null,
    );
  }

  Color _colorFor(String s) {
    const palette = [
      Color(0xFF6C63FF), Color(0xFF03DAC6), Color(0xFFFF6584),
      Color(0xFFFFB347), Color(0xFF57CC99), Color(0xFF4FC3F7),
    ];
    if (s.isEmpty) return palette[0];
    return palette[s.codeUnitAt(0) % palette.length];
  }
}

class _UnreadBadge extends StatelessWidget {
  final int count;
  const _UnreadBadge({required this.count});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: const Color(0xFF6C63FF),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Text(
        count > 99 ? '99+' : '$count',
        style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.bold),
      ),
    );
  }
}
