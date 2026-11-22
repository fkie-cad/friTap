import 'package:flutter_test/flutter_test.dart';
import 'package:flutterhttps/main.dart';

void main() {
  test('nonce is 16 hex chars and unique', () {
    final a = newNonce(), b = newNonce();
    expect(RegExp(r'^[0-9a-f]{16}$').hasMatch(a), isTrue);
    expect(a, isNot(b));
  });

  test('request urls embed the nonce', () {
    expect(groundTruthRequests.first.urlFor('abc'), contains('fritap-abc'));
    expect(groundTruthRequests[2].bodyFor!('abc'), contains('"fritap_nonce":"abc"'));
  });
}
