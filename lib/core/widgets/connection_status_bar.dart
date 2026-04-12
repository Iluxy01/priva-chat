import 'package:flutter/material.dart';
import '../services/websocket_service.dart';
import '../services/presence_service.dart';

/// Тонкая полоска вверху экрана — показывает статус WebSocket.
/// Невидима когда connected.
class ConnectionStatusBar extends StatelessWidget {
  const ConnectionStatusBar({super.key});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: WebSocketService.instance,
      builder: (context, _) {
        final status = WebSocketService.instance.status;
        if (status == WsStatus.connected) return const SizedBox.shrink();

        final (label, color) = switch (status) {
          WsStatus.connecting   => ('Подключение...', const Color(0xFFFFA000)),
          WsStatus.reconnecting => ('Переподключение...', const Color(0xFFFFA000)),
          WsStatus.disconnected => ('Нет соединения', const Color(0xFFE53935)),
          WsStatus.connected    => ('', Colors.transparent),
        };

        return AnimatedContainer(
          duration: const Duration(milliseconds: 300),
          width: double.infinity,
          color: color,
          padding: const EdgeInsets.symmetric(vertical: 5),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              if (status != WsStatus.disconnected) ...[
                const SizedBox(
                  width: 12,
                  height: 12,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation(Colors.white),
                  ),
                ),
                const SizedBox(width: 8),
              ],
              Text(
                label,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        );
      },
    );
  }
}

/// Зелёная/серая точка онлайн-статуса пользователя.
class OnlineIndicator extends StatelessWidget {
  final int userId;
  final double size;
  const OnlineIndicator({super.key, required this.userId, this.size = 10});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: PresenceService.instance,
      builder: (context, _) {
        final online = PresenceService.instance.isOnline(userId);
        return AnimatedContainer(
          duration: const Duration(milliseconds: 300),
          width: size,
          height: size,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: online ? const Color(0xFF4CAF50) : Colors.grey,
            border: Border.all(
              color: Theme.of(context).scaffoldBackgroundColor,
              width: size * 0.15,
            ),
          ),
        );
      },
    );
  }
}

/// Текст "в сети" / "был(а) N мин назад" для шапки чата.
class OnlineStatusText extends StatelessWidget {
  final int userId;
  final TextStyle? style;
  const OnlineStatusText({super.key, required this.userId, this.style});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: PresenceService.instance,
      builder: (context, _) {
        final online   = PresenceService.instance.isOnline(userId);
        final lastSeen = PresenceService.instance.lastSeen(userId);
        return Text(
          online ? 'в сети' : _fmt(lastSeen),
          style: (style ?? const TextStyle(fontSize: 12))
              .copyWith(color: online ? const Color(0xFF4CAF50) : Colors.grey),
        );
      },
    );
  }

  String _fmt(String? iso) {
    if (iso == null) return 'не в сети';
    try {
      final diff = DateTime.now().difference(DateTime.parse(iso).toLocal());
      if (diff.inSeconds < 60) return 'только что';
      if (diff.inMinutes < 60) return 'был(а) ${diff.inMinutes} мин назад';
      if (diff.inHours < 24)   return 'был(а) ${diff.inHours} ч назад';
      if (diff.inDays == 1)    return 'был(а) вчера';
      return 'был(а) ${diff.inDays} дн назад';
    } catch (_) {
      return 'не в сети';
    }
  }
}
