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
/// sessionStorage) under `publicKey.name`, as `iv.ciphertext`.
///
/// Where the key is stored:
/// - By default: as a non-extractable `CryptoKey` in the IndexedDB database
///   `dbName`, object store `keys`, under `publicKey`. Scripts on the page
///   can use the key but cannot export its bytes. The browser does not
///   necessarily encrypt the key at rest: Chrome and Firefox write its bytes
///   to the profile unencrypted, so a copy of the profile can decrypt the
///   values.
/// - With `useSessionStorage`: as raw bytes in sessionStorage under
///   `publicKey`, so that the key ends with the session, like the values.
/// - With `wrapKey`: wrapped with `wrapKey`, in the selected storage under
///   `publicKey`.
///
/// Earlier versions stored the raw key in localStorage under `publicKey`.
/// The first operation that needs the key moves it to IndexedDB as a
/// non-extractable key with the same bytes, so existing values stay
/// readable, and then removes it from localStorage.
///
/// Every operation reads the key from where it is stored. After `deleteAll`
/// in one tab, other tabs do not keep using the deleted key.
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

  bool _usesSessionStorage(Map<String, String> options) =>
      options[_useSessionStorage] == 'true';

  web.Storage _getStorage(Map<String, String> options) {
    return _usesSessionStorage(options)
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

  bool _usesWrapKey(Map<String, String> options) =>
      options[_wrapKey]?.isNotEmpty ?? false;

  /// Whether the key is a non-extractable CryptoKey in IndexedDB.
  bool _usesIndexedDb(Map<String, String> options) =>
      !_usesWrapKey(options) && !_usesSessionStorage(options);

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async {
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

    if (_usesIndexedDb(options)) {
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
  /// [publicKey] itself (raw or wrapped).
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
  /// Returns null if the key does not exist or if decryption fails. Throws
  /// if the encryption key cannot be loaded.
  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    final value = _getStorage(options).getItem('${options[_publicKey]!}.$key');
    if (value == null) return null;

    final encryptionKey = await _getEncryptionKey(options, create: false);
    if (encryptionKey == null) return null;
    return _decryptValue(value, encryptionKey);
  }

  /// Decrypts and returns all keys with associated values.
  ///
  /// Values that cannot be decrypted are left out. Throws if the encryption
  /// key cannot be loaded.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final storage = _getStorage(options);
    final map = <String, String>{};
    final prefix = '${options[_publicKey]!}.';

    final keys = <String>[];
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (key.startsWith(prefix)) keys.add(key);
    }
    if (keys.isEmpty) return map;

    final encryptionKey = await _getEncryptionKey(options, create: false);
    if (encryptionKey == null) return map;

    for (final key in keys) {
      final cypherText = storage.getItem(key);
      if (cypherText == null) continue;
      final value = await _decryptValue(cypherText, encryptionKey);
      if (value == null) continue;
      map[key.substring(prefix.length)] = value;
    }

    return map;
  }

  js_interop.JSAny _getAlgorithm(Uint8List iv) {
    return {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!;
  }

  js_interop.JSAny get _keyAlgorithm =>
      {'name': 'AES-GCM', 'length': 256}.jsify()!;

  /// Loads the key from where [options] say it is stored. If there is none,
  /// creates and stores one when [create] is true, and returns null when it
  /// is false.
  Future<web.CryptoKey?> _getEncryptionKey(
    Map<String, String> options, {
    required bool create,
  }) {
    return _usesIndexedDb(options)
        ? _getIndexedDbKey(options, create: create)
        : _getStorageKey(options, create: create);
  }

  /// The non-extractable key in IndexedDB. Moves a raw key of an earlier
  /// version from localStorage first.
  Future<web.CryptoKey?> _getIndexedDbKey(
    Map<String, String> options, {
    required bool create,
  }) async {
    final publicKey = options[_publicKey]!;
    final db = await _openDatabase(_getDbName(options));
    try {
      final stored = await _loadKey(db, publicKey);
      if (stored != null) return stored;

      final localStorage = web.window.localStorage;
      final rawKey = localStorage.getItem(publicKey);
      web.CryptoKey key;
      if (rawKey != null) {
        // Keep the bytes, so the values encrypted with them stay readable.
        key = await _crypto.subtle
            .importKey(
              'raw',
              base64Decode(rawKey).toJS,
              _keyAlgorithm,
              false,
              ['encrypt', 'decrypt'].toJS,
            )
            .toDart;
      } else if (create) {
        key = (await _crypto.subtle
            .generateKey(_keyAlgorithm, false, ['encrypt', 'decrypt'].toJS)
            .toDart)! as web.CryptoKey;
      } else {
        return null;
      }

      // `add` fails if another tab or call stored a key meanwhile. Then use
      // that key, so that every writer uses the same key. Two calls that
      // move the same raw key store the same bytes.
      try {
        await _idbRequest<js_interop.JSAny?>(
          _keyStore(db, 'readwrite').add(key, publicKey.toJS),
        );
      } on _IdbRequestError catch (e) {
        if (e.name != 'ConstraintError') rethrow;
        final winner = await _loadKey(db, publicKey);
        if (winner == null) {
          throw StateError('IndexedDB key for "$publicKey" disappeared');
        }
        key = winner;
      }

      if (rawKey != null && localStorage.getItem(publicKey) == rawKey) {
        localStorage.removeItem(publicKey);
      }
      return key;
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

  /// The key stored in localStorage or sessionStorage under `publicKey`:
  /// wrapped with `wrapKey` if set, raw otherwise.
  Future<web.CryptoKey?> _getStorageKey(
    Map<String, String> options, {
    required bool create,
  }) async {
    final storage = _getStorage(options);
    final name = options[_publicKey]!;

    final stored = storage.getItem(name);
    if (stored != null) return _importStorageKey(stored, options);
    if (!create) return null;

    // Extractable, so that it can be wrapped or exported.
    final created = (await _crypto.subtle
        .generateKey(_keyAlgorithm, true, ['encrypt', 'decrypt'].toJS)
        .toDart)! as web.CryptoKey;
    final js_interop.JSAny? exported;
    if (_usesWrapKey(options)) {
      exported = await _crypto.subtle
          .wrapKey(
            'raw',
            created,
            await _getWrapKey(options),
            _getWrapAlgorithm(options),
          )
          .toDart;
    } else {
      exported = await _crypto.subtle.exportKey('raw', created).toDart;
    }

    // A concurrent call in this tab may have stored a key during the awaits
    // above. Use that one. No await between this check and setItem.
    final winner = storage.getItem(name);
    if (winner != null) return _importStorageKey(winner, options);
    storage.setItem(
      name,
      base64Encode(
        (exported! as js_interop.JSArrayBuffer).toDart.asUint8List(),
      ),
    );
    return created;
  }

  Future<web.CryptoKey> _importStorageKey(
    String stored,
    Map<String, String> options,
  ) async {
    final bytes = base64Decode(stored).toJS;
    if (_usesWrapKey(options)) {
      return _crypto.subtle
          .unwrapKey(
            'raw',
            bytes,
            await _getWrapKey(options),
            _getWrapAlgorithm(options),
            _keyAlgorithm,
            false,
            ['encrypt', 'decrypt'].toJS,
          )
          .toDart;
    }
    return _crypto.subtle
        .importKey(
          'raw',
          bytes,
          _keyAlgorithm,
          false,
          ['encrypt', 'decrypt'].toJS,
        )
        .toDart;
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

    final encryptionKey = (await _getEncryptionKey(options, create: true))!;

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

  /// Returns null if [cypherText] is malformed or [key] does not decrypt it.
  Future<String?> _decryptValue(String cypherText, web.CryptoKey key) async {
    try {
      final parts = cypherText.split('.');
      final iv = base64Decode(parts[0]);
      final value = base64Decode(parts[1]);

      final decryptedContent = await _crypto.subtle
          .decrypt(
            _getAlgorithm(iv),
            key,
            Uint8List.fromList(value).toJS,
          )
          .toDart;

      return utf8.decode(
        (decryptedContent! as js_interop.JSArrayBuffer).toDart.asUint8List(),
      );
    } on Object catch (e, s) {
      if (kDebugMode) {
        print(e);
        debugPrintStack(stackTrace: s);
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
