@TestOn('browser')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop' as js_interop;
import 'dart:typed_data';

import 'package:flutter_secure_storage_web/flutter_secure_storage_web.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:web/web.dart' as web;

/// Returns a fresh instance.
FlutterSecureStorageWeb _freshInstance(String testId) {
  return FlutterSecureStorageWeb();
}

Map<String, String> _optionsForTest(String testId) => {
      'publicKey': 'TestKey_$testId',
      'dbName': 'TestDB_$testId',
      'wrapKey': '',
      'wrapKeyIv': '',
      'useSessionStorage': 'false',
    };

Future<void> _cleanup(String testId) async {
  final storage = FlutterSecureStorageWeb();
  final options = _optionsForTest(testId);
  await storage.deleteAll(options: options);

  // Also clean up localStorage directly.
  final ls = web.window.localStorage;
  final keyName = options['publicKey']!;
  ls.removeItem(keyName);

  // Delete the IndexedDB database.
  web.window.indexedDB.deleteDatabase(options['dbName']!);
}

void main() {
  // -------------------------------------------------------------------------
  // Basic CRUD
  // -------------------------------------------------------------------------

  group('Basic CRUD', () {
    const testId = 'crud';

    tearDown(() => _cleanup(testId));

    test('write then read returns same value', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'greeting', value: 'hello', options: options);
      final result = await storage.read(key: 'greeting', options: options);

      expect(result, 'hello');
    });

    test('read non-existent key returns null', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      final result = await storage.read(key: 'nonexistent', options: options);

      expect(result, isNull);
    });

    test('overwrite replaces value', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'k', value: 'first', options: options);
      await storage.write(key: 'k', value: 'second', options: options);
      final result = await storage.read(key: 'k', options: options);

      expect(result, 'second');
    });

    test('containsKey returns true for existing key', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'exists', value: 'yes', options: options);

      expect(
        await storage.containsKey(key: 'exists', options: options),
        isTrue,
      );
    });

    test('containsKey returns false for missing key', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      expect(
        await storage.containsKey(key: 'nope', options: options),
        isFalse,
      );
    });

    test('delete removes a key', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'del', value: 'bye', options: options);
      await storage.delete(key: 'del', options: options);

      expect(await storage.read(key: 'del', options: options), isNull);
      expect(
        await storage.containsKey(key: 'del', options: options),
        isFalse,
      );
    });

    test('deleteAll removes all keys', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'a', value: '1', options: options);
      await storage.write(key: 'b', value: '2', options: options);
      await storage.write(key: 'c', value: '3', options: options);
      await storage.deleteAll(options: options);

      expect(await storage.readAll(options: options), isEmpty);
    });

    test('readAll returns all written keys', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'x', value: 'alpha', options: options);
      await storage.write(key: 'y', value: 'beta', options: options);
      final all = await storage.readAll(options: options);

      expect(all, {'x': 'alpha', 'y': 'beta'});
    });
  });

  // -------------------------------------------------------------------------
  // Encryption properties
  // -------------------------------------------------------------------------

  group('Encryption properties', () {
    const testId = 'enc';

    tearDown(() => _cleanup(testId));

    test('stored value in localStorage is not plaintext', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;
      const secret = 'super_secret_password_123';

      await storage.write(key: 'pw', value: secret, options: options);

      final raw = web.window.localStorage.getItem('$keyName.pw');

      // Must exist in localStorage.
      expect(raw, isNotNull);
      // Must NOT contain the plaintext.
      expect(raw, isNot(contains(secret)));
      // Must be in the IV.ciphertext format.
      expect(raw!.split('.'), hasLength(2));
    });

    test('different writes of same value produce different ciphertext (random IV)', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;

      await storage.write(key: 'a', value: 'same', options: options);
      final raw1 = web.window.localStorage.getItem('$keyName.a');

      // Delete and re-write to force a new IV.
      await storage.delete(key: 'a', options: options);
      await storage.write(key: 'a', value: 'same', options: options);
      final raw2 = web.window.localStorage.getItem('$keyName.a');

      // Ciphertext should differ due to random IV.
      expect(raw1, isNot(equals(raw2)));
    });

    test('raw encryption key bytes are NOT in localStorage', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;

      // Trigger key generation by writing a value.
      await storage.write(key: 'trigger', value: 'val', options: options);

      // The legacy implementation stored raw key bytes here.
      // Our implementation must NOT.
      final legacyKey = web.window.localStorage.getItem(keyName);
      expect(
        legacyKey,
        isNull,
        reason: 'Raw encryption key bytes must not exist in localStorage. '
            'Key should be a non-extractable CryptoKey in IndexedDB.',
      );
    });

    test('CryptoKey exists in IndexedDB', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;
      final dbName = options['dbName']!;

      // Trigger key generation.
      await storage.write(key: 'trigger', value: 'val', options: options);

      // Open IndexedDB directly and verify the key is there.
      final key = await _loadKeyFromIdb(dbName, keyName);
      expect(
        key,
        isNotNull,
        reason: 'CryptoKey should be stored in IndexedDB',
      );
    });

    test('CryptoKey in IndexedDB is not extractable', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;
      final dbName = options['dbName']!;

      // Trigger key generation.
      await storage.write(key: 'trigger', value: 'val', options: options);

      // Open IndexedDB directly and verify extractable is false.
      final key = await _loadKeyFromIdb(dbName, keyName);
      expect(key, isNotNull);
      expect(
        key!.extractable,
        isFalse,
        reason: 'CryptoKey must be generated with extractable: false',
      );

      // Verify exportKey actually throws.
      expect(
        () => web.window.crypto.subtle
            .exportKey('raw', key)
            .toDart,
        throwsA(anything),
        reason: 'Exporting a non-extractable key must throw',
      );
    });
  });

  // -------------------------------------------------------------------------
  // Unicode & edge cases
  // -------------------------------------------------------------------------

  group('Unicode & edge cases', () {
    const testId = 'unicode';

    tearDown(() => _cleanup(testId));

    test('handles unicode values', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      const value = '🔒 日本語 العربية émojis 🎉';
      await storage.write(key: 'uni', value: value, options: options);

      expect(await storage.read(key: 'uni', options: options), value);
    });

    test('handles empty string value', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      await storage.write(key: 'empty', value: '', options: options);

      expect(await storage.read(key: 'empty', options: options), '');
    });

    test('handles very long value', () async {
      final storage = _freshInstance(testId);
      final options = _optionsForTest(testId);

      final longValue = 'x' * 100000;
      await storage.write(key: 'long', value: longValue, options: options);

      expect(await storage.read(key: 'long', options: options), longValue);
    });
  });

  // -------------------------------------------------------------------------
  // Legacy migration
  // -------------------------------------------------------------------------

  group('Legacy migration', () {
    const testId = 'migrate';

    tearDown(() => _cleanup(testId));

    test('migrates legacy localStorage key to IndexedDB', () async {
      final options = _optionsForTest(testId);
      final keyName = options['publicKey']!;
      final dbName = options['dbName']!;
      final ls = web.window.localStorage;

      // Simulate the OLD implementation: generate an extractable key,
      // export raw bytes, store in localStorage.
      final algorithm =
          {'name': 'AES-GCM', 'length': 256}.jsify()! as js_interop.JSObject;
      final legacyKey = (await web.window.crypto.subtle
          .generateKey(algorithm, true, ['encrypt', 'decrypt'].toJS)
          .toDart)! as web.CryptoKey;

      final rawBytes = (await web.window.crypto.subtle
              .exportKey('raw', legacyKey)
              .toDart)! as js_interop.JSArrayBuffer;
      final legacyKeyB64 = base64Encode(rawBytes.toDart.asUint8List());

      // Store legacy key in localStorage (this is what old code did).
      ls.setItem(keyName, legacyKeyB64);

      // Encrypt a value with the legacy key (simulating old write).
      final iv = (web.window.crypto.getRandomValues(Uint8List(12).toJS)
              as js_interop.JSUint8Array)
          .toDart;
      final ivAlgo =
          {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!;
      final encrypted = (await web.window.crypto.subtle
              .encrypt(
                ivAlgo,
                legacyKey,
                Uint8List.fromList(utf8.encode('legacy_secret')).toJS,
              )
              .toDart)! as js_interop.JSArrayBuffer;
      final cipherB64 = base64Encode(encrypted.toDart.asUint8List());
      ls.setItem('$keyName.migrated_val', '${base64Encode(iv)}.$cipherB64');

      // Now use the NEW implementation — it should migrate.
      final storage = _freshInstance(testId);
      final result = await storage.read(
        key: 'migrated_val',
        options: options,
      );

      // Value should be readable.
      expect(result, 'legacy_secret');

      // Legacy key should be GONE from localStorage.
      expect(
        ls.getItem(keyName),
        isNull,
        reason: 'Legacy key must be deleted from localStorage after migration',
      );

      // New key should be in IndexedDB.
      final idbKey = await _loadKeyFromIdb(dbName, keyName);
      expect(idbKey, isNotNull);
      expect(idbKey!.extractable, isFalse);
    });
  });

  // -------------------------------------------------------------------------
  // Isolation between instances/options
  // -------------------------------------------------------------------------

  group('Isolation', () {
    const testIdA = 'isolate_a';
    const testIdB = 'isolate_b';

    tearDown(() async {
      await _cleanup(testIdA);
      await _cleanup(testIdB);
    });

    test('different dbName/publicKey are isolated', () async {
      final storageA = _freshInstance(testIdA);
      final storageB = _freshInstance(testIdB);
      final optionsA = _optionsForTest(testIdA);
      final optionsB = _optionsForTest(testIdB);

      await storageA.write(key: 'shared', value: 'A', options: optionsA);
      await storageB.write(key: 'shared', value: 'B', options: optionsB);

      expect(await storageA.read(key: 'shared', options: optionsA), 'A');
      expect(await storageB.read(key: 'shared', options: optionsB), 'B');
    });
  });

  // -------------------------------------------------------------------------
  // Persistence across instances
  // -------------------------------------------------------------------------

  group('Persistence', () {
    const testId = 'persist';

    tearDown(() => _cleanup(testId));

    test('value persists across new FlutterSecureStorageWeb instances',
        () async {
      final options = _optionsForTest(testId);

      final storage1 = _freshInstance(testId);
      await storage1.write(key: 'persist', value: 'stays', options: options);

      // Create a totally new instance (simulates app reload).
      final storage2 = FlutterSecureStorageWeb();
      final result = await storage2.read(key: 'persist', options: options);

      expect(result, 'stays');
    });
  });
}

// ---------------------------------------------------------------------------
// Test helpers — direct IndexedDB access
// ---------------------------------------------------------------------------

extension on List<String> {
  js_interop.JSArray<js_interop.JSString> get toJS => [
        ...map((e) => e.toJS),
      ].toJS;
}

Future<web.CryptoKey?> _loadKeyFromIdb(String dbName, String keyName) async {
  final openRequest = web.window.indexedDB.open(dbName, 1);

  openRequest.onupgradeneeded = ((web.IDBVersionChangeEvent event) {
    final target = event.target as web.IDBOpenDBRequest;
    final db = target.result as web.IDBDatabase;
    if (!db.objectStoreNames.contains('keys')) {
      db.createObjectStore('keys');
    }
  }).toJS;

  final db = await _idbRequestToFuture<web.IDBDatabase>(openRequest);

  final tx = db.transaction('keys'.toJS, 'readonly');
  final store = tx.objectStore('keys');
  final getRequest = store.get(keyName.toJS);
  final result = await _idbRequestToFuture<js_interop.JSAny?>(getRequest);

  db.close();

  if (result == null || result.isUndefinedOrNull) return null;
  return result as web.CryptoKey;
}

Future<T> _idbRequestToFuture<T>(web.IDBRequest request) {
  final completer = Completer<T>();
  request.onsuccess = ((web.Event _) {
    completer.complete(request.result as T);
  }).toJS;
  request.onerror = ((web.Event _) {
    completer.completeError(
      StateError('IDBRequest failed'),
    );
  }).toJS;
  return completer.future;
}
