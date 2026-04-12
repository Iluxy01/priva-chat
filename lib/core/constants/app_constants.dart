class AppConstants {
  // ← ЗАМЕНИ на свой URL с Render
  static const serverUrl = 'https://private-server-int8.onrender.com';
  static const wsUrl = 'wss://private-server-int8.onrender.com';

  // Для локальной разработки (Android эмулятор):
  // static const serverUrl = 'http://10.0.2.2:3000';
  // static const wsUrl = 'ws://10.0.2.2:3000';

  static const tokenKey = 'auth_token';
  static const userIdKey = 'user_id';
  static const privateKeyKey = 'private_key';
  static const publicKeyKey = 'public_key';
}
