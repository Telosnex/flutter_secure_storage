@TestOn('browser')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop' as js_interop;
import 'dart:typed_data';

import 'package:flutter_secure_storage_web/flutter_secure_storage_web.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:web/web.dart' as web;

// Tests for where the key is stored: IndexedDB by default, sessionStorage
// with useSessionStorage, and moving a raw key of an earlier version.

Map<String, String> _options(
  String publicKey, {
  String dbName = 'CryptoKeyTestDB',
  bool session = false,
}) =>
    {
      'publicKey': publicKey,
      'dbName': dbName,
      'wrapKey': '',
      'wrapKeyIv': '',
      'useSessionStorage': session.toString(),
    };

var _counter = 0;

/// A database name that no other test uses.
String _freshDb() =>
    'CryptoKeyTestDB_${DateTime.now().microsecondsSinceEpoch}_${_counter++}';

void main() {
  late String db;

  setUp(() {
    db = _freshDb();
    web.window.localStorage.clear();
    web.window.sessionStorage.clear();
  });

  tearDown(() async {
    web.window.localStorage.clear();
    web.window.sessionStorage.clear();
    await _deleteDatabase(db);
  });

  group('key storage', () {
    test('the raw key is not in localStorage', () async {
      final options = _options('K', dbName: db);
      await FlutterSecureStorageWeb()
          .write(key: 'a', value: 'v', options: options);

      expect(web.window.localStorage.getItem('K'), isNull);
      expect(web.window.localStorage.length, 1);
    });

    test('the key is in IndexedDB and cannot be exported', () async {
      final options = _options('K', dbName: db);
      await FlutterSecureStorageWeb()
          .write(key: 'a', value: 'v', options: options);

      final key = await _loadKey(db, 'K');
      expect(key, isNotNull);
      expect(key!.extractable, isFalse);
      await expectLater(
        web.window.crypto.subtle.exportKey('raw', key).toDart,
        throwsA(anything),
      );
    });

    test('stored values are not plaintext and use a random IV', () async {
      final options = _options('K', dbName: db);
      final storage = FlutterSecureStorageWeb();
      await storage.write(key: 'a', value: 'secret', options: options);
      final first = web.window.localStorage.getItem('K.a');
      await storage.write(key: 'a', value: 'secret', options: options);
      final second = web.window.localStorage.getItem('K.a');

      expect(first, isNot(contains('secret')));
      expect(first!.split('.'), hasLength(2));
      expect(first, isNot(second));
    });

    test('values survive a new instance (page reload)', () async {
      final options = _options('K', dbName: db);
      await FlutterSecureStorageWeb()
          .write(key: 'a', value: 'stays', options: options);

      expect(
        await FlutterSecureStorageWeb().read(key: 'a', options: options),
        'stays',
      );
    });

    test('unicode, empty and long values round-trip', () async {
      final options = _options('K', dbName: db);
      final storage = FlutterSecureStorageWeb();
      final values = {'u': '🔒 日本語 العربية', 'e': '', 'l': 'x' * 100000};
      for (final e in values.entries) {
        await storage.write(key: e.key, value: e.value, options: options);
      }

      expect(await storage.readAll(options: options), values);
    });
  });

  group('concurrent first use', () {
    test('one instance: concurrent writes share one key', () async {
      final options = _options('K', dbName: db);
      final storage = FlutterSecureStorageWeb();
      await Future.wait([
        for (var i = 0; i < 10; i++)
          storage.write(key: 'k$i', value: 'v$i', options: options),
      ]);

      final fresh = FlutterSecureStorageWeb();
      expect(await fresh.readAll(options: options), {
        for (var i = 0; i < 10; i++) 'k$i': 'v$i',
      });
    });

    test('two instances (two tabs): concurrent writes share one key', () async {
      final options = _options('K', dbName: db);
      final a = FlutterSecureStorageWeb();
      final b = FlutterSecureStorageWeb();
      await Future.wait([
        a.write(key: 'a', value: 'from a', options: options),
        b.write(key: 'b', value: 'from b', options: options),
      ]);

      final fresh = FlutterSecureStorageWeb();
      expect(
        await fresh.readAll(options: options),
        {'a': 'from a', 'b': 'from b'},
      );
    });
  });

  group('namespaces in one database', () {
    test('each public key has its own key', () async {
      final a = _options('A', dbName: db);
      final b = _options('B', dbName: db);
      final storage = FlutterSecureStorageWeb();
      await storage.write(key: 'k', value: 'A', options: a);
      await storage.write(key: 'k', value: 'B', options: b);

      final fresh = FlutterSecureStorageWeb();
      expect(await fresh.read(key: 'k', options: a), 'A');
      expect(await fresh.read(key: 'k', options: b), 'B');
      expect(await _loadKey(db, 'A'), isNotNull);
      expect(await _loadKey(db, 'B'), isNotNull);
    });

    test('deleteAll removes only its own values and key', () async {
      final a = _options('A', dbName: db);
      final b = _options('B', dbName: db);
      final storage = FlutterSecureStorageWeb();
      await storage.write(key: 'k', value: 'A', options: a);
      await storage.write(key: 'k', value: 'B', options: b);

      await storage.deleteAll(options: a);

      expect(await _loadKey(db, 'A'), isNull);
      expect(await storage.readAll(options: a), isEmpty);
      expect(await storage.read(key: 'k', options: b), 'B');
      expect(
        await FlutterSecureStorageWeb().read(key: 'k', options: b),
        'B',
      );
    });

    test('writing after deleteAll creates a new key', () async {
      final options = _options('K', dbName: db);
      final storage = FlutterSecureStorageWeb();
      await storage.write(key: 'a', value: '1', options: options);
      final before = await _loadKey(db, 'K');
      await storage.deleteAll(options: options);
      await storage.write(key: 'a', value: '2', options: options);

      expect(await _loadKey(db, 'K'), isNot(same(before)));
      expect(
        await FlutterSecureStorageWeb().read(key: 'a', options: options),
        '2',
      );
    });
  });

  group('earlier versions', () {
    /// Stores a raw key and one value the way earlier versions did.
    Future<void> legacy(String publicKey, String name, String value) async {
      final key = await _generateExtractableKey();
      final raw = (await web.window.crypto.subtle.exportKey('raw', key).toDart)!
          as js_interop.JSArrayBuffer;
      web.window.localStorage
        ..setItem(publicKey, base64Encode(raw.toDart.asUint8List()))
        ..setItem('$publicKey.$name', await _encrypt(key, value));
    }

    test('a read moves the raw key to IndexedDB and keeps the values',
        () async {
      final options = _options('K', dbName: db);
      final ls = web.window.localStorage;
      await legacy('K', 'old', 'legacy');
      ls.setItem('Other.x', 'untouched');

      expect(
        await FlutterSecureStorageWeb().read(key: 'old', options: options),
        'legacy',
      );

      expect(ls.getItem('K'), isNull);
      expect(ls.getItem('Other.x'), 'untouched');
      expect((await _loadKey(db, 'K'))!.extractable, isFalse);
      expect(
        await FlutterSecureStorageWeb().read(key: 'old', options: options),
        'legacy',
      );
    });

    test('a first write moves the raw key and old values stay readable',
        () async {
      final options = _options('K', dbName: db);
      await legacy('K', 'old', 'legacy');

      await FlutterSecureStorageWeb()
          .write(key: 'new', value: 'v', options: options);

      expect(web.window.localStorage.getItem('K'), isNull);
      expect(
        await FlutterSecureStorageWeb().readAll(options: options),
        {'old': 'legacy', 'new': 'v'},
      );
    });

    test('two tabs moving the same raw key at once agree', () async {
      final options = _options('K', dbName: db);
      await legacy('K', 'old', 'legacy');
      final a = FlutterSecureStorageWeb();
      final b = FlutterSecureStorageWeb();

      await Future.wait([
        a.write(key: 'a', value: 'from a', options: options),
        b.write(key: 'b', value: 'from b', options: options),
        a.read(key: 'old', options: options),
        b.read(key: 'old', options: options),
      ]);

      expect(
        await FlutterSecureStorageWeb().readAll(options: options),
        {'old': 'legacy', 'a': 'from a', 'b': 'from b'},
      );
    });
  });

  group('other tabs', () {
    test('after deleteAll in one tab, another tab writes with a live key',
        () async {
      final options = _options('K', dbName: db);
      final a = FlutterSecureStorageWeb();
      final b = FlutterSecureStorageWeb();
      await a.write(key: 'k', value: 'old', options: options);
      expect(await b.read(key: 'k', options: options), 'old');

      await a.deleteAll(options: options);
      await b.write(key: 'k', value: 'new', options: options);

      expect(
        await FlutterSecureStorageWeb().read(key: 'k', options: options),
        'new',
      );
      expect(await a.read(key: 'k', options: options), 'new');
    });

    test('reads do not create a key', () async {
      final options = _options('K', dbName: db);
      final storage = FlutterSecureStorageWeb();
      expect(await storage.read(key: 'k', options: options), isNull);
      expect(await storage.readAll(options: options), isEmpty);
      web.window.localStorage.setItem('K.orphan', 'AAAA.AAAA');
      expect(await storage.read(key: 'k', options: options), isNull);
      expect(await storage.readAll(options: options), isEmpty);

      expect(await _loadKey(db, 'K'), isNull);
    });
  });

  group('wrapKey', () {
    test('uses the wrapped key in storage, not IndexedDB', () async {
      final wrapKey = Uint8List(32);
      final iv = Uint8List(12);
      web.window.crypto
        ..getRandomValues(wrapKey.toJS)
        ..getRandomValues(iv.toJS);
      final options = {
        ..._options('W', dbName: db),
        'wrapKey': base64Encode(wrapKey),
        'wrapKeyIv': base64Encode(iv),
      };
      await FlutterSecureStorageWeb()
          .write(key: 'a', value: 'wrapped', options: options);

      expect(web.window.localStorage.getItem('W'), isNotNull);
      expect(await _loadKey(db, 'W'), isNull);
      expect(
        await FlutterSecureStorageWeb().read(key: 'a', options: options),
        'wrapped',
      );
    });
  });

  group('sessionStorage', () {
    test('the key is in sessionStorage, not IndexedDB', () async {
      final options = _options('S', dbName: db, session: true);
      await FlutterSecureStorageWeb()
          .write(key: 'a', value: 'v', options: options);

      expect(web.window.sessionStorage.getItem('S.a'), isNotNull);
      expect(web.window.sessionStorage.getItem('S'), isNotNull);
      expect(web.window.localStorage.length, 0);
      expect(await _loadKey(db, 'S'), isNull);
      expect(
        await FlutterSecureStorageWeb().read(key: 'a', options: options),
        'v',
      );
    });

    test('concurrent first writes in one tab share one key', () async {
      final options = _options('S', dbName: db, session: true);
      final storage = FlutterSecureStorageWeb();
      await Future.wait([
        for (var i = 0; i < 10; i++)
          storage.write(key: 'k$i', value: 'v$i', options: options),
      ]);

      expect(await FlutterSecureStorageWeb().readAll(options: options), {
        for (var i = 0; i < 10; i++) 'k$i': 'v$i',
      });
    });

    test('deleteAll removes the key with the values', () async {
      final options = _options('S', dbName: db, session: true);
      final storage = FlutterSecureStorageWeb();
      await storage.write(key: 'a', value: 'v', options: options);

      await storage.deleteAll(options: options);

      expect(web.window.sessionStorage.length, 0);
      expect(await storage.read(key: 'a', options: options), isNull);
    });
  });
}

extension on List<String> {
  js_interop.JSArray<js_interop.JSString> get toJS =>
      [...map((e) => e.toJS)].toJS;
}

Future<web.CryptoKey> _generateExtractableKey() async =>
    (await web.window.crypto.subtle
        .generateKey(
          {'name': 'AES-GCM', 'length': 256}.jsify()!,
          true,
          ['encrypt', 'decrypt'].toJS,
        )
        .toDart)! as web.CryptoKey;

Future<String> _encrypt(web.CryptoKey key, String value) async {
  final iv = Uint8List(12);
  web.window.crypto.getRandomValues(iv.toJS);
  final encrypted = (await web.window.crypto.subtle
      .encrypt(
        {'name': 'AES-GCM', 'length': 256, 'iv': iv}.jsify()!,
        key,
        Uint8List.fromList(utf8.encode(value)).toJS,
      )
      .toDart)! as js_interop.JSArrayBuffer;
  return '${base64Encode(iv)}.'
      '${base64Encode(encrypted.toDart.asUint8List())}';
}

Future<web.CryptoKey?> _loadKey(String dbName, String publicKey) async {
  final open = web.window.indexedDB.open(dbName, 1);
  open.onupgradeneeded = ((web.IDBVersionChangeEvent _) {
    (open.result! as web.IDBDatabase).createObjectStore('keys');
  }).toJS;
  final db = await _request<web.IDBDatabase>(open);
  try {
    final result = await _request<js_interop.JSAny?>(
      db.transaction('keys'.toJS, 'readonly').objectStore('keys').get(
            publicKey.toJS,
          ),
    );
    if (result == null || result.isUndefinedOrNull) return null;
    return result as web.CryptoKey;
  } finally {
    db.close();
  }
}

Future<void> _deleteDatabase(String dbName) =>
    _request<js_interop.JSAny?>(web.window.indexedDB.deleteDatabase(dbName));

Future<T> _request<T extends js_interop.JSAny?>(web.IDBRequest request) {
  final completer = Completer<T>();
  request
    ..onsuccess = ((web.Event _) {
      completer.complete(request.result as T);
    }).toJS
    ..onerror = ((web.Event _) {
      completer
          .completeError(StateError('IDBRequest failed: ${request.error}'));
    }).toJS;
  return completer.future;
}
