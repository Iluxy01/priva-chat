class UserModel {
  final int id;
  final String username;
  final String displayName;
  final String? avatarUrl;
  final String? status;
  final String? publicKey;
  final String? lastSeen;

  const UserModel({
    required this.id,
    required this.username,
    required this.displayName,
    this.avatarUrl,
    this.status,
    this.publicKey,
    this.lastSeen,
  });

  factory UserModel.fromJson(Map<String, dynamic> j) => UserModel(
        id: j['id'],
        username: j['username'],
        displayName: j['display_name'],
        avatarUrl: j['avatar_url'],
        status: j['status'],
        publicKey: j['public_key'],
        lastSeen: j['last_seen'],
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'username': username,
        'display_name': displayName,
        'avatar_url': avatarUrl,
        'status': status,
        'public_key': publicKey,
        'last_seen': lastSeen,
      };
}
