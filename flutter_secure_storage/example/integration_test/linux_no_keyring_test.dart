import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Linux: unavailable keyring reports a PlatformException', (
    tester,
  ) async {
    const storage = FlutterSecureStorage();

    await expectLater(
      storage.read(key: 'unavailable-keyring-probe'),
      throwsA(
        isA<PlatformException>()
            .having((error) => error.code, 'code', 'Libsecret error')
            .having(
              (error) => error.message,
              'message',
              contains('secret_service_get_sync'),
            ),
      ),
    );
  });
}
