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

import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:cryptography/cryptography.dart';

import '../web_crypto/web_crypto.dart' as web_crypto;

/// _RSA-PSS_ signature algorithm. __Currently supported only in browsers__. The
/// hash algorithm must be [sha256], [sha384], or [sha512].
///
/// By default, key size is [defaultModulusLength] (4096 bits).
///
/// ## Example
/// ```
/// import 'package:cryptography/cryptography.dart';
///
/// Future<void> main() async {
///   const algorithm = RsaPss(sha256);
///   final keyPair = await algorithm.newKeyPair();
///   final signature = await algorithm.sign([1,2,3], keyPair);
///   final isOk = await algorithm.verify([1,2,3], signature);
/// }
/// ```
class RsaOaep {
  static const int defaultModulusLength = 2048;
  static const List<int> defaultPublicExponent = [0x01, 0x00, 0x01];

  const RsaOaep();

  String get name => 'rsaOaep';

  Future<KeyPair> newKeyPair({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
    @required String format,
  }) {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.rsaNewKeyPairForEncryption(
        name: 'RSA-OAEP',
        modulusLength: modulusLength,
        publicExponent: publicExponent,
        format: format,
      );
    }
    throw UnimplementedError();
  }

  KeyPair newKeyPairSync({
    int modulusLength = defaultModulusLength,
    List<int> publicExponent = defaultPublicExponent,
  }) {
    throw UnimplementedError(
      '$name newKeyPair() is not supported on the current platform. Try asynchronous method?',
    );
  }

  Future<Uint8List> encrypt(List<int> input, KeyPair keyPair) {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.rsaOaepEncrypt(
        input,
        keyPair
      );
    }
    throw UnimplementedError(
      '$name encrypt() is not supported on the current platform.',
    );
  }

  Future<Uint8List> decrypt(
    List<int> input, 
    KeyPair keyPair, {
    @required int modulusLength,
  }) {
    if (web_crypto.isWebCryptoSupported) {
      return web_crypto.rsaOaepDecrypt(
        input,
        keyPair,
        modulusLength: modulusLength,
      );
    }
    throw UnimplementedError(
      '$name decrypt() is not supported on the current platform.',
    );
  }
}
