// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/utils.dart';

const kPrivatePemHeader = '-----BEGIN PRIVATE KEY-----';
const kPrivatePemFooter = '-----END PRIVATE KEY-----';

const kPublicPemHeader = '-----BEGIN PUBLIC KEY-----';
const kPublicPemFooter = '-----END PUBLIC KEY-----';

class PEMPrivateKey extends PrivateKey {
  String content;
  List<int> _bytes;

  PEMPrivateKey() : super.constructor();

  @override
  List<int> extractSync() => utf8.encode(content);

  List<int> get bytes => _bytes;

  @override
  bool operator ==(other) =>
      other is PEMPrivateKey &&
      constantTimeBytesEquality.equals(bytes, other.bytes);

  List<int> toPEM() {
    var bytes = _bytes;
    content = base64.encode(bytes);

      return utf8
          .encode('$kPrivatePemHeader\r\n$content\r\n$kPrivatePemFooter');
  }

  static PEMPrivateKey fromRawBytes(List<int> bytes) {
    final key = PEMPrivateKey();
    key._bytes = bytes;
    final content = base64.encode(bytes);
    key.content = content;
    return key;
  }

  /// Constructs a private key from the bytes.
  static PEMPrivateKey fromBytes(List<int> bytes) {
    return fromPEM(utf8.decode(bytes));
  }

  /// Constructs a private key from the JSON tree.
  static PEMPrivateKey fromPEM(String pemContent) {
    if (pemContent.startsWith(kPrivatePemHeader)) {
      return fromPKCS8(pemContent);
    } else {
      throw ArgumentError.value('Invalid PEM private key: $pemContent');
    }
  }

  static PEMPrivateKey fromPKCS8(String pkcs8Content) {
    final b64data = pkcs8Content
        .replaceFirst(kPrivatePemHeader, '')
        .replaceFirst(kPrivatePemFooter, '')
        .replaceAll(RegExp(r'\s+'), '');

    final key = PEMPrivateKey();
    key._bytes = base64.decode(b64data).toList();
    key.content = pkcs8Content;
    return key;
  }
}

/// Superclass for public keys that use JWK ([RFC 7517](https://tools.ietf.org/html/rfc7517):
/// "JSON Web Key") storage format.
///
/// ## Implementations
///   * [EcJwkPublicKey]
///   * [RsaJwkPublicKey].
class PEMPublicKey extends PublicKey {
  String content;
  List<int> _bytes;

  PEMPublicKey() : super.constructor();

  @override
  List<int> get bytes => _bytes;

  List<int> extractSync() => utf8.encode(content);

  @override
  bool operator ==(other) =>
      other is JwkPublicKey &&
      constantTimeBytesEquality.equals(bytes, other.bytes);

  List<int> toPEM({bool spki = true}) {
    content = base64.encode(_bytes);
    return utf8.encode('$kPublicPemHeader\r\n$content\r\n$kPublicPemFooter');
  }

  static PEMPublicKey fromRawBytes(List<int> bytes) {
    final key = PEMPublicKey();
    key._bytes = bytes;
    final content = base64.encode(bytes);
    key.content = content;
    return key;
  }

  /// Constructs a private key from the JSON tree.
  static PEMPublicKey fromPEM(String pemContent) {
    if (pemContent.startsWith(kPublicPemHeader)) {
      return fromSPKI(pemContent);
    } else {
      throw ArgumentError.value('Invalid PEM Public key: $pemContent');
    }
  }

  static PEMPublicKey fromSPKI(String pkcs8Content) {
    final b64data = pkcs8Content
        .replaceFirst(kPublicPemHeader, '')
        .replaceFirst(kPublicPemFooter, '')
        .replaceAll(RegExp(r'\s+'), '');

    final key = PEMPublicKey();
    key._bytes = base64.decode(b64data).toList();
    key.content = pkcs8Content;
    return key;
  }
}
