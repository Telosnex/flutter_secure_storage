/// Web library for flutter_secure_storage
library;

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop' as js_interop;
import 'dart:js_interop_unsafe' as js_interop;

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:web/web.dart' as web;

/// Web implementation of FlutterSecureStorage
///
/// Values are encrypted with AES-256-GCM and stored in localStorage (or
/// sessionStorage) as `iv.ciphertext`.
///
/// The key is a non-extractable `CryptoKey`. It is stored in the IndexedDB
/// database `dbName`, object store `keys`, under the `publicKey` name.
/// Scripts on the page can use the key, but cannot read its bytes, so a copy
/// of the browser storage alone does not decrypt the values.
///
/// When `wrapKey` is set, the key is wrapped with it and stored in
/// localStorage under `publicKey`, as before.
///
/// Earlier versions stored the raw key bytes in localStorage under
/// `publicKey`. When no IndexedDB key exists yet, such a raw key and the
/// values encrypted with it are deleted. Those values are not migrated.
class FlutterSecureStorageWeb extends FlutterSecureStoragePlatform {
  static const _publicKey = 'publicKey';
  static const _dbName = 'dbName';
  static const _wrapKey = 'wrapKey';
  static const _wrapKeyIv = 'wrapKeyIv';
  static const _useSessionStorage = 'useSessionStorage';

  /// Registrar for FlutterSecureStorageWeb
  static void registerWith(Registrar registrar) {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWeb();
  }

  web.Crypto get _crypto {
    if (web.window.isSecureContext) {
      return web.window.crypto;
    }

    throw UnsupportedError(
      'FlutterSecureStorageWeb only works in secure contexts '
      'Refer to the documentation for more information: '
      'https://pub.dev/packages/flutter_secure_storage#configure-web-version',
    );
  }

  web.Storage _getStorage(Map<String, String> options) {
    return options[_useSessionStorage] == 'true'
        ? web.window.sessionStorage
        : web.window.localStorage;
  }

  String _getDbName(Map<String, String> options) {
    final dbName = options[_dbName];
    return dbName == null || dbName.isEmpty ? _defaultDbName : dbName;
  }

  static const _defaultDbName = 'FlutterEncryptedStorage';

  /// IndexedDB object store that holds the CryptoKeys.
  static const _idbStoreName = 'keys';

  /// Keys being loaded or loaded, by database and public key. One future per
  /// key, so concurrent first calls share one key.
  final _keys = <String, Future<web.CryptoKey>>{};

  String _keyId(Map<String, String> options) =>
      '${_getDbName(options)}\u0000${options[_publicKey]!}';

  bool _usesWrapKey(Map<String, String> options) =>
      options[_wrapKey]?.isNotEmpty ?? false;

  /// If a raw key of an earlier version is in storage, sets up the key now,
  /// which deletes the raw key and its values. Call before reading values.
  Future<void> _dropEarlierVersionKey(Map<String, String> options) async {
    if (_usesWrapKey(options)) return;
    if (!_getStorage(options).has(options[_publicKey]!)) return;
    await _getEncryptionKey(_getAlgorithm(Uint8List(12)), options);
  }

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async {
    await _dropEarlierVersionKey(options);
    return _getStorage(options).has('${options[_publicKey]!}.$key');
  }

  /// Deletes associated value for the given [key].
  ///
  /// If the given [key] does not exist, nothing will happen.
  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
    _getStorage(options).removeItem('${options[_publicKey]!}.$key');
  }

  /// Deletes all keys with associated values.
  @override
  Future<void> deleteAll({
    required Map<String, String> options,
  }) async {
    final publicKey = options[_publicKey]!;
    _removeValuesAndStoredKey(_getStorage(options), publicKey);

    if (!_usesWrapKey(options)) {
      // Let a pending load finish first, so it cannot store a key after
      // the delete.
      final pending = _keys.remove(_keyId(options));
      if (pending != null) {
        await pending.then<void>((_) {}, onError: (Object _) {});
      }
      final db = await _openDatabase(_getDbName(options));
      try {
        await _idbRequest<js_interop.JSAny?>(
          _keyStore(db, 'readwrite').delete(publicKey.toJS),
        );
      } finally {
        db.close();
      }
    }
  }

  /// Removes the values of [publicKey] and the key stored in [storage] under
  /// [publicKey] itself (wrapped, or raw from earlier versions).
  void _removeValuesAndStoredKey(web.Storage storage, String publicKey) {
    final keys = [publicKey];
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (!key.startsWith('$publicKey.')) {
        continue;
      }

      keys.add(key);
    }

    // ignore: prefer_foreach, tearoffs of interop members are disallowed
    for (final key in keys) {
      storage.removeItem(key);
    }
  }

  /// Reads and decrypts the value for the given [key].
  ///
  /// Returns null if the key does not exist or if decryption fails.
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    await _dropEarlierVersionKey(options);
    final value = _getStorage(options).getItem('${options[_publicKey]!}.$key');

    return _decryptValue(value, options);
  }

  /// Decrypts and returns all keys with associated values.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    await _dropEarlierVersionKey(options);
    final storage = _getStorage(options);
    final map = <String, String>{};
    final prefix = '${options[_publicKey]!}.';

    final keys = <String>[];
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (key.startsWith(prefix)) keys.add(key);
    }

    for (final key in keys) {
      final value = await _decryptValue(storage.getItem(key), options);
      if (value == null) continue;
      map[key.substring(prefix.length)] = value;
    }

    return map;
  }

  js_interop.JSAny _getAlgorithm(Uint8List iv) {
    return {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!;
  }

  Future<web.CryptoKey> _getEncryptionKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    if (_usesWrapKey(options)) {
      return _getWrappedEncryptionKey(algorithm, options);
    }

    // No await before this line, so concurrent callers share one future.
    final id = _keyId(options);
    var loading = _keys[id];
    if (loading == null) {
      loading = _loadOrCreateKey(algorithm, options);
      _keys[id] = loading;
    }
    try {
      return await loading;
    } on Object {
      // Allow a retry after a failure.
      if (identical(_keys[id], loading)) {
        // The removed future is the one awaited above.
        unawaited(_keys.remove(id));
      }
      rethrow;
    }
  }

  /// Loads the non-extractable key from IndexedDB, or creates and stores it.
  Future<web.CryptoKey> _loadOrCreateKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    final publicKey = options[_publicKey]!;
    final db = await _openDatabase(_getDbName(options));
    try {
      final stored = await _loadKey(db, publicKey);
      if (stored != null) return stored;

      // Raw key of an earlier version, and the values it encrypted.
      _removeValuesAndStoredKey(_getStorage(options), publicKey);

      final created = (await _crypto.subtle
          .generateKey(algorithm, false, ['encrypt', 'decrypt'].toJS)
          .toDart)! as web.CryptoKey;

      // `add` fails if another tab or instance stored a key meanwhile. Then
      // use that key, so that every writer uses the same key.
      try {
        await _idbRequest<js_interop.JSAny?>(
          _keyStore(db, 'readwrite').add(created, publicKey.toJS),
        );
        return created;
      } on _IdbRequestError catch (e) {
        if (e.name != 'ConstraintError') rethrow;
      }

      final winner = await _loadKey(db, publicKey);
      if (winner == null) {
        throw StateError('IndexedDB key for "$publicKey" disappeared');
      }
      return winner;
    } finally {
      db.close();
    }
  }

  Future<web.CryptoKey?> _loadKey(web.IDBDatabase db, String publicKey) async {
    final result = await _idbRequest<js_interop.JSAny?>(
      _keyStore(db, 'readonly').get(publicKey.toJS),
    );
    if (result == null || result.isUndefinedOrNull) return null;
    return result as web.CryptoKey;
  }

  web.IDBObjectStore _keyStore(web.IDBDatabase db, String mode) =>
      db.transaction(_idbStoreName.toJS, mode).objectStore(_idbStoreName);

  Future<web.IDBDatabase> _openDatabase(String dbName) {
    final request = web.window.indexedDB.open(dbName, 1);
    request.onupgradeneeded = ((web.IDBVersionChangeEvent _) {
      final db = request.result! as web.IDBDatabase;
      if (!db.objectStoreNames.contains(_idbStoreName)) {
        db.createObjectStore(_idbStoreName);
      }
    }).toJS;
    return _idbRequest<web.IDBDatabase>(request);
  }

  Future<T> _idbRequest<T extends js_interop.JSAny?>(web.IDBRequest request) {
    final completer = Completer<T>();
    request
      ..onsuccess = ((web.Event _) {
        completer.complete(request.result as T);
      }).toJS
      ..onerror = ((web.Event event) {
        // Handled here; do not let the error abort the transaction loudly.
        event.preventDefault();
        final error = request.error;
        completer.completeError(
          _IdbRequestError(error?.name ?? 'UnknownError', error?.message),
        );
      }).toJS;
    return completer.future;
  }

  /// The key wrapped with `wrapKey`, stored in localStorage (or
  /// sessionStorage) under `publicKey`.
  Future<web.CryptoKey> _getWrappedEncryptionKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    final storage = _getStorage(options);
    late web.CryptoKey encryptionKey;
    final key = options[_publicKey]!;

    if (storage.has(key)) {
      final jwk = base64Decode(storage.getItem(key)!);
      final unwrappingKey = await _getWrapKey(options);
      final unwrapAlgorithm = _getWrapAlgorithm(options);
      encryptionKey = await _crypto.subtle
          .unwrapKey(
            'raw',
            jwk.toJS,
            unwrappingKey,
            unwrapAlgorithm,
            algorithm,
            false,
            ['encrypt', 'decrypt'].toJS,
          )
          .toDart;
    } else {
      // Extractable, so that it can be wrapped.
      encryptionKey = (await _crypto.subtle
          .generateKey(algorithm, true, ['encrypt', 'decrypt'].toJS)
          .toDart)! as web.CryptoKey;

      final wrappingKey = await _getWrapKey(options);
      final wrapAlgorithm = _getWrapAlgorithm(options);
      final jsonWebKey = await _crypto.subtle
          .wrapKey(
            'raw',
            encryptionKey,
            wrappingKey,
            wrapAlgorithm,
          )
          .toDart;

      storage.setItem(
        key,
        base64Encode(
          (jsonWebKey! as js_interop.JSArrayBuffer).toDart.asUint8List(),
        ),
      );
    }

    return encryptionKey;
  }

  Future<web.CryptoKey> _getWrapKey(Map<String, String> options) async {
    final wrapKey = base64Decode(options[_wrapKey]!);
    final algorithm = _getWrapAlgorithm(options);
    return _crypto.subtle
        .importKey(
          'raw',
          wrapKey.toJS,
          algorithm,
          true,
          ['wrapKey', 'unwrapKey'].toJS,
        )
        .toDart;
  }

  js_interop.JSAny _getWrapAlgorithm(Map<String, String> options) {
    final iv = base64Decode(options[_wrapKeyIv]!);
    return _getAlgorithm(iv);
  }

  /// Encrypts and saves the [key] with the given [value].
  ///
  /// If the key was already in the storage, its associated value is changed.
  /// If the value is null, deletes associated value for the given [key].
  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    final iv =
        (_crypto.getRandomValues(Uint8List(12).toJS) as js_interop.JSUint8Array)
            .toDart;

    final algorithm = _getAlgorithm(iv);

    final encryptionKey = await _getEncryptionKey(algorithm, options);

    final encryptedContent = (await _crypto.subtle
        .encrypt(
          algorithm,
          encryptionKey,
          Uint8List.fromList(
            utf8.encode(value),
          ).toJS,
        )
        .toDart)! as js_interop.JSArrayBuffer;

    final encoded = '${base64Encode(iv)}.'
        '${base64Encode(encryptedContent.toDart.asUint8List())}';

    _getStorage(options).setItem('${options[_publicKey]!}.$key', encoded);
  }

  Future<String?> _decryptValue(
    String? cypherText,
    Map<String, String> options,
  ) async {
    if (cypherText != null) {
      try {
        final parts = cypherText.split('.');

        final iv = base64Decode(parts[0]);
        final algorithm = _getAlgorithm(iv);

        final decryptionKey = await _getEncryptionKey(algorithm, options);

        final value = base64Decode(parts[1]);

        final decryptedContent = await _crypto.subtle
            .decrypt(
              _getAlgorithm(iv),
              decryptionKey,
              Uint8List.fromList(value).toJS,
            )
            .toDart;

        final plainText = utf8.decode(
          (decryptedContent! as js_interop.JSArrayBuffer).toDart.asUint8List(),
        );

        return plainText;
      } on Exception catch (e, s) {
        if (kDebugMode) {
          print(e);
          debugPrintStack(stackTrace: s);
        }
      }
    }

    return null;
  }
}

extension on List<String> {
  js_interop.JSArray<js_interop.JSString> get toJS => [
        ...map((e) => e.toJS),
      ].toJS;
}

class _IdbRequestError implements Exception {
  _IdbRequestError(this.name, this.message);

  final String name;
  final String? message;

  @override
  String toString() => 'IndexedDB request failed: $name: $message';
}
