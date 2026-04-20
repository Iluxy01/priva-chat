import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'core/theme/app_theme.dart';
import 'core/services/auth_service.dart';
import 'core/services/presence_service.dart';
import 'core/services/key_exchange_service.dart';
import 'core/crypto/encryption_service.dart';
import 'core/database/app_database.dart';
import 'core/services/local_storage_service.dart';
import 'features/auth/screens/login_screen.dart';
import 'features/auth/screens/register_screen.dart';
import 'features/chats/screens/chats_list_screen.dart';
import 'features/chats/screens/chat_screen.dart';
import 'features/chats/screens/create_group_screen.dart';
import 'features/chats/screens/group_info_screen.dart';
import 'features/profile/screens/profile_screen.dart';
import 'features/search/screens/user_search_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  print('[main] 🚀 Запуск PrivaChat...');

  // Инициализируем локальную БД
  print('[main] Инициализация локальной БД...');
  final db = AppDatabase();
  LocalStorageService.instance.init(db);
  print('[main] БД готова ✅');

  // Инициализируем сервис присутствия
  PresenceService.instance.init();

  // Если пользователь уже залогинен — инициализируем шифрование и обмен ключами
  final loggedIn = await AuthService.isLoggedIn();
  print('[main] Пользователь залогинен: $loggedIn');

  if (loggedIn) {
    print('[main] Загружаем ключи шифрования...');
    try {
      await EncryptionService.ensureKeys();
      print('[main] Ключи шифрования готовы ✅');
    } catch (e) {
      print('[main] ⚠️ Ошибка загрузки ключей: $e');
    }

    print('[main] Запускаем KeyExchangeService...');
    KeyExchangeService.instance.init();
    print('[main] KeyExchangeService запущен ✅');
  }

  print('[main] runApp...');
  runApp(const PrivaChatApp());
}

final _router = GoRouter(
  initialLocation: '/login',
  redirect: (context, state) async {
    final loggedIn = await AuthService.isLoggedIn();
    final onAuth = state.matchedLocation == '/login' ||
        state.matchedLocation == '/register';
    if (loggedIn && onAuth) return '/chats';
    if (!loggedIn && !onAuth) return '/login';
    return null;
  },
  routes: [
    GoRoute(path: '/login',    builder: (_, __) => const LoginScreen()),
    GoRoute(path: '/register', builder: (_, __) => const RegisterScreen()),
    GoRoute(path: '/chats',    builder: (_, __) => const ChatsListScreen()),
    GoRoute(path: '/profile',  builder: (_, __) => const ProfileScreen()),
    GoRoute(path: '/search',   builder: (_, __) => const UserSearchScreen()),
    GoRoute(path: '/create-group', builder: (_, __) => const CreateGroupScreen()),
    GoRoute(
      path: '/chat/:id',
      builder: (_, state) =>
          ChatScreen(chatId: int.parse(state.pathParameters['id']!)),
    ),
    GoRoute(
      path: '/group-info/:id',
      builder: (_, state) =>
          GroupInfoScreen(chatId: int.parse(state.pathParameters['id']!)),
    ),
  ],
);

class PrivaChatApp extends StatelessWidget {
  const PrivaChatApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: 'PrivaChat',
      theme: AppTheme.light(),
      darkTheme: AppTheme.dark(),
      themeMode: ThemeMode.system,
      routerConfig: _router,
      debugShowCheckedModeBanner: false,
    );
  }
}
