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
/// Encrypts values with AES-256-GCM using a CryptoKey that is:
///   1. Generated with `extractable: false` — the raw key bytes can never
///      be read by JavaScript.
///   2. Stored in IndexedDB as an opaque CryptoKey object — IndexedDB can
///      store structured-cloneable objects like CryptoKey without extracting
///      them.
///
/// Encrypted values (IV + ciphertext) are stored in localStorage/sessionStorage
/// as before.
///
/// **Migration:** On first access, if a legacy key exists in localStorage
/// (raw bytes, base64-encoded — the old format), it is imported as a NEW
/// non-extractable key, re-encrypting all existing values. The legacy key
/// is then deleted from localStorage.
class FlutterSecureStorageWeb extends FlutterSecureStoragePlatform {
  static const _publicKey = 'publicKey';
  static const _dbName = 'dbName';
  static const _wrapKey = 'wrapKey';
  static const _wrapKeyIv = 'wrapKeyIv';
  static const _useSessionStorage = 'useSessionStorage';

  /// IndexedDB object store name for CryptoKey storage.
  static const _idbStoreName = 'keys';

  /// IndexedDB version.
  static const _idbVersion = 1;

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
    return options[_dbName]?.isNotEmpty ?? false
        ? options[_dbName]!
        : 'FlutterEncryptedStorage';
  }

  // ---------------------------------------------------------------------------
  // IndexedDB helpers
  // ---------------------------------------------------------------------------

  /// Opens (or creates) the IndexedDB database for CryptoKey storage.
  Future<web.IDBDatabase> _openDatabase(String dbName) async {
    final request = web.window.indexedDB.open(dbName, _idbVersion);

    // Create object store on first open / version upgrade.
    request.onupgradeneeded = ((web.IDBVersionChangeEvent event) {
      final target = event.target as web.IDBOpenDBRequest;
      final db = target.result as web.IDBDatabase;
      if (!db.objectStoreNames.contains(_idbStoreName)) {
        db.createObjectStore(_idbStoreName);
      }
    }).toJS;

    return _waitForRequest<web.IDBDatabase>(request);
  }

  /// Stores a CryptoKey in IndexedDB under [keyName].
  Future<void> _storeKeyInIdb(
    web.IDBDatabase db,
    String keyName,
    web.CryptoKey key,
  ) async {
    final tx = db.transaction(_idbStoreName.toJS, 'readwrite');
    final store = tx.objectStore(_idbStoreName);
    final request = store.put(key as js_interop.JSAny, keyName.toJS);
    await _waitForRequest<js_interop.JSAny?>(request);
  }

  /// Loads a CryptoKey from IndexedDB by [keyName]. Returns null if not found.
  Future<web.CryptoKey?> _loadKeyFromIdb(
    web.IDBDatabase db,
    String keyName,
  ) async {
    final tx = db.transaction(_idbStoreName.toJS, 'readonly');
    final store = tx.objectStore(_idbStoreName);
    final request = store.get(keyName.toJS);
    final result = await _waitForRequest<js_interop.JSAny?>(request);
    if (result == null || result.isUndefinedOrNull) return null;
    return result as web.CryptoKey;
  }

  /// Deletes all keys from IndexedDB.
  Future<void> _clearIdb(web.IDBDatabase db) async {
    final tx = db.transaction(_idbStoreName.toJS, 'readwrite');
    final store = tx.objectStore(_idbStoreName);
    final request = store.clear();
    await _waitForRequest<js_interop.JSAny?>(request);
  }

  /// Waits for an IDBRequest to complete and returns the result.
  Future<T> _waitForRequest<T>(web.IDBRequest request) {
    final completer = Completer<T>();
    request.onsuccess = ((web.Event _) {
      completer.complete(request.result as T);
    }).toJS;
    request.onerror = ((web.Event _) {
      completer.completeError(
        StateError('IndexedDB request failed: ${request.error}'),
      );
    }).toJS;
    return completer.future;
  }

  // ---------------------------------------------------------------------------
  // Encryption key management
  // ---------------------------------------------------------------------------

  /// Cached encryption keys per db name to avoid repeated IndexedDB lookups.
  final _keyCache = <String, web.CryptoKey>{};

  /// Gets or creates the AES-256-GCM encryption key.
  ///
  /// Key is stored as a non-extractable CryptoKey in IndexedDB.
  /// If a legacy key exists in localStorage (from the old implementation),
  /// it is migrated: all existing values are re-encrypted with a new
  /// non-extractable key, and the legacy key is deleted.
  Future<web.CryptoKey> _getEncryptionKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    final dbName = _getDbName(options);
    final keyName = options[_publicKey]!;

    // Fast path: cached key.
    if (_keyCache.containsKey(dbName)) {
      return _keyCache[dbName]!;
    }

    // Check for wrapKey mode — delegate to legacy behavior.
    final useWrapKey = options[_wrapKey]?.isNotEmpty ?? false;
    if (useWrapKey) {
      return _getWrappedKey(algorithm, options);
    }

    final db = await _openDatabase(dbName);

    try {
      // Try loading from IndexedDB first.
      final existingKey = await _loadKeyFromIdb(db, keyName);
      if (existingKey != null) {
        _keyCache[dbName] = existingKey;
        return existingKey;
      }

      // Check for legacy key in localStorage.
      final storage = _getStorage(options);
      final legacyKeyB64 = storage.getItem(keyName);

      if (legacyKeyB64 != null) {
        // Migrate: generate new non-extractable key, re-encrypt all values.
        final newKey = await _generateNonExtractableKey(algorithm);
        await _migrateLegacyKey(
          legacyKeyB64,
          newKey,
          algorithm,
          options,
          storage,
          keyName,
        );
        await _storeKeyInIdb(db, keyName, newKey);
        storage.removeItem(keyName); // Delete legacy key from localStorage.
        _keyCache[dbName] = newKey;
        return newKey;
      }

      // No key anywhere — generate a fresh non-extractable key.
      final newKey = await _generateNonExtractableKey(algorithm);
      await _storeKeyInIdb(db, keyName, newKey);
      _keyCache[dbName] = newKey;
      return newKey;
    } finally {
      db.close();
    }
  }

  /// Generates a new AES-256-GCM key with `extractable: false`.
  Future<web.CryptoKey> _generateNonExtractableKey(
    js_interop.JSAny algorithm,
  ) async {
    return (await _crypto.subtle
        .generateKey(algorithm, false, ['encrypt', 'decrypt'].toJS)
        .toDart)! as web.CryptoKey;
  }

  /// Migrates all values encrypted with the legacy (extractable) key to a
  /// new non-extractable key.
  Future<void> _migrateLegacyKey(
    String legacyKeyB64,
    web.CryptoKey newKey,
    js_interop.JSAny algorithm,
    Map<String, String> options,
    web.Storage storage,
    String keyName,
  ) async {
    // Import the legacy key (extractable, since we have the raw bytes).
    final legacyBytes = base64Decode(legacyKeyB64);
    final legacyKey = await _crypto.subtle
        .importKey(
          'raw',
          legacyBytes.toJS,
          algorithm,
          false,
          ['decrypt'].toJS,
        )
        .toDart;

    // Find all encrypted values in storage.
    final prefix = '$keyName.';
    final keysToMigrate = <String>[];
    for (var j = 0; j < storage.length; j++) {
      final k = storage.key(j) ?? '';
      if (k.startsWith(prefix)) {
        keysToMigrate.add(k);
      }
    }

    // Re-encrypt each value: decrypt with legacy key, encrypt with new key.
    for (final storageKey in keysToMigrate) {
      final cipherText = storage.getItem(storageKey);
      if (cipherText == null) continue;

      try {
        final parts = cipherText.split('.');
        if (parts.length != 2) continue;

        final oldIv = base64Decode(parts[0]);
        final oldCipher = base64Decode(parts[1]);

        // Decrypt with legacy key.
        final decrypted = await _crypto.subtle
            .decrypt(
              _getAlgorithm(oldIv),
              legacyKey,
              Uint8List.fromList(oldCipher).toJS,
            )
            .toDart;

        // Encrypt with new key using fresh IV.
        final newIv =
            (_crypto.getRandomValues(Uint8List(12).toJS)
                    as js_interop.JSUint8Array)
                .toDart;
        final newAlgorithm = _getAlgorithm(newIv);
        final encrypted = (await _crypto.subtle
            .encrypt(
              newAlgorithm,
              newKey,
              (decrypted! as js_interop.JSArrayBuffer).toDart.asUint8List().toJS,
            )
            .toDart)! as js_interop.JSArrayBuffer;

        final encoded = '${base64Encode(newIv)}.'
            '${base64Encode(encrypted.toDart.asUint8List())}';
        storage.setItem(storageKey, encoded);
      } on Exception catch (e, s) {
        // If a single value fails to migrate, log and continue.
        // The value will be unreadable (wrong key) — same as data loss,
        // but better than blocking migration of all other values.
        if (kDebugMode) {
          print('Migration failed for $storageKey: $e');
          debugPrintStack(stackTrace: s);
        }
      }
    }
  }

  /// Legacy wrapKey support. When a wrapKey is provided, we can't use
  /// IndexedDB (the caller is providing their own key management).
  /// Falls back to the original localStorage-based approach.
  Future<web.CryptoKey> _getWrappedKey(
    js_interop.JSAny algorithm,
    Map<String, String> options,
  ) async {
    final storage = _getStorage(options);
    final key = options[_publicKey]!;

    if (storage.has(key)) {
      final jwk = base64Decode(storage.getItem(key)!);
      final unwrappingKey = await _getWrapKey(options);
      final unwrapAlgorithm = _getWrapAlgorithm(options);
      return _crypto.subtle
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
      // Generate extractable (must be to wrap it).
      final encryptionKey = (await _crypto.subtle
          .generateKey(algorithm, true, ['encrypt', 'decrypt'].toJS)
          .toDart)! as web.CryptoKey;

      final wrappingKey = await _getWrapKey(options);
      final wrapAlgorithm = _getWrapAlgorithm(options);
      final wrapped = await _crypto.subtle
          .wrapKey('raw', encryptionKey, wrappingKey, wrapAlgorithm)
          .toDart;

      storage.setItem(
        key,
        base64Encode(
          (wrapped! as js_interop.JSArrayBuffer).toDart.asUint8List(),
        ),
      );

      return encryptionKey;
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// Returns true if the storage contains the given [key].
  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) =>
      Future.value(
        _getStorage(options).has('${options[_publicKey]!}.$key'),
      );

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
    final storage = _getStorage(options);
    final publicKey = options[_publicKey]!;
    final keys = <String>[];
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (key.startsWith('$publicKey.')) {
        keys.add(key);
      }
    }

    for (final key in keys) {
      storage.removeItem(key);
    }

    // Also clear the IndexedDB key.
    final dbName = _getDbName(options);
    _keyCache.remove(dbName);
    try {
      final db = await _openDatabase(dbName);
      await _clearIdb(db);
      db.close();
    } on Exception catch (e, s) {
      if (kDebugMode) {
        print('Failed to clear IndexedDB: $e');
        debugPrintStack(stackTrace: s);
      }
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
    final value = _getStorage(options).getItem('${options[_publicKey]!}.$key');

    return _decryptValue(value, options);
  }

  /// Decrypts and returns all keys with associated values.
  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async {
    final storage = _getStorage(options);
    final map = <String, String>{};
    final prefix = '${options[_publicKey]!}.';
    for (var j = 0; j < storage.length; j++) {
      final key = storage.key(j) ?? '';
      if (!key.startsWith(prefix)) {
        continue;
      }

      final value = await _decryptValue(storage.getItem(key), options);

      if (value == null) {
        continue;
      }

      map[key.substring(prefix.length)] = value;
    }

    return map;
  }

  js_interop.JSAny _getAlgorithm(Uint8List iv) {
    return {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!;
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
