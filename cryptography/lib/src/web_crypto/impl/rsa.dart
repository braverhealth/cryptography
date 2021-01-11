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

part of web_crypto;

@override
Future<KeyPair> rsaNewKeyPairForSigning({
  @required String name,
  @required int modulusLength,
  @required List<int> publicExponent,
  @required String hashName,
}) async {
  ArgumentError.checkNotNull(name);
  ArgumentError.checkNotNull(modulusLength);
  ArgumentError.checkNotNull(publicExponent);
  ArgumentError.checkNotNull(hashName);
  // Generate CryptoKeyPair
  final jsCryptoKeyPair =
      await js.promiseToFuture<web_crypto.CryptoKeyPair>(web_crypto.generateKey(
    web_crypto.RsaHashedKeyGenParams(
      name: name,
      modulusLength: modulusLength,
      publicExponent: Uint8List.fromList(publicExponent),
      hash: hashName,
    ),
    true,
    ['sign', 'verify'],
  ));

  // Export to JWK
  final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
    web_crypto.exportKey('jwk', jsCryptoKeyPair.privateKey),
  );

  // Construct a keys
  final privateKey = RsaJwkPrivateKey(
    n: _base64UrlDecode(jsJwk.n),
    e: _base64UrlDecode(jsJwk.e),
    d: _base64UrlDecode(jsJwk.d),
    p: _base64UrlDecode(jsJwk.p),
    q: _base64UrlDecode(jsJwk.q),
    dp: _base64UrlDecode(jsJwk.dp),
    dq: _base64UrlDecode(jsJwk.dq),
    qi: _base64UrlDecode(jsJwk.qi),
  );

  final publicKey = privateKey.toPublicKey();

  // Cache Web Cryptography keys
  privateKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.privateKey;
  publicKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.publicKey;

  // Return a key pair
  return KeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

@override
Future<KeyPair> rsaNewKeyPairForEncryption({
  @required String name,
  @required int modulusLength,
  @required List<int> publicExponent,
  @required String format,
}) async {
  ArgumentError.checkNotNull(name);
  ArgumentError.checkNotNull(modulusLength);
  ArgumentError.checkNotNull(publicExponent);

  PublicKey publicKey;
  PrivateKey privateKey;

  // Generate CryptoKeyPair
  final jsCryptoKeyPair =
      await js.promiseToFuture<web_crypto.CryptoKeyPair>(web_crypto.generateKey(
    web_crypto.RsaHashedKeyGenParams(
      name: name,
      modulusLength: modulusLength,
      publicExponent: Uint8List.fromList(publicExponent),
      hash: 'SHA-256',
    ),
    true,
    ['encrypt', 'decrypt'],
  ));

  if (format == 'jwk') {
    // Export to JWK
    final jsJwk = await js.promiseToFuture<web_crypto.Jwk>(
      web_crypto.exportKey('jwk', jsCryptoKeyPair.privateKey),
    );

    // Construct a keys
    privateKey = RsaJwkPrivateKey(
      n: _base64UrlDecode(jsJwk.n),
      e: _base64UrlDecode(jsJwk.e),
      d: _base64UrlDecode(jsJwk.d),
      p: _base64UrlDecode(jsJwk.p),
      q: _base64UrlDecode(jsJwk.q),
      dp: _base64UrlDecode(jsJwk.dp),
      dq: _base64UrlDecode(jsJwk.dq),
      qi: _base64UrlDecode(jsJwk.qi),
    );

    publicKey = (privateKey as RsaJwkPrivateKey).toPublicKey();

    // Cache Web Cryptography keys
    privateKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.privateKey;
    publicKey.cachedValues[_webCryptoKeyCachingKey] = jsCryptoKeyPair.publicKey;
  } else if (format == 'pem') {
    // Export to PKCS8
    final privateData = await js.promiseToFuture<ByteBuffer>(
      web_crypto.exportKey('pkcs8', jsCryptoKeyPair.privateKey),
    );
    final publicData = await js.promiseToFuture<ByteBuffer>(
      web_crypto.exportKey('spki', jsCryptoKeyPair.publicKey),
    );

    // Construct a keys
    privateKey = PEMPrivateKey.fromRawBytes(Uint8List.view(privateData).toList());
    publicKey = PEMPublicKey.fromRawBytes(Uint8List.view(publicData).toList());

    // Cache Web Cryptography keys
    privateKey.cachedValues['decrypt'] = jsCryptoKeyPair.privateKey;
    publicKey.cachedValues['encrypt'] = jsCryptoKeyPair.publicKey;
  } else {
    throw ArgumentError.value('Format invalid: $format (only "pem" and "jwk" are accepted)');
  }

  // Return a key pair
  return KeyPair(
    privateKey: privateKey,
    publicKey: publicKey,
  );
}

@override
Future<Uint8List> rsaOaepEncrypt(
  List<int> plainText, 
  KeyPair keyPair,
) async {
  ArgumentError.checkNotNull(plainText, 'plainText');
  ArgumentError.checkNotNull(keyPair, 'keyPair');

  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.encrypt(
      web_crypto.RsaOaepParams(
        name: 'RSA-OAEP',
      ),
      await _rsaCryptoKeyFromPublicKey(
        keyPair.publicKey, 
        name: 'RSA-OAEP',
        hashName: 'SHA-256',
        usage: 'encrypt',
      ),
      _jsArrayBufferFrom(plainText),
    ),
  );
  return Uint8List.view(byteBuffer);
}

@override
Future<Uint8List> rsaOaepDecrypt(
  List<int> plainText, 
  KeyPair keyPair, {
  @required int modulusLength
}) async {
  ArgumentError.checkNotNull(plainText, 'plainText');
  ArgumentError.checkNotNull(keyPair, 'keyPair');
  ArgumentError.checkNotNull(modulusLength, 'modulusLength');

  final byteBuffer = await js.promiseToFuture<ByteBuffer>(
    web_crypto.decrypt(
      web_crypto.RsaOaepParams(
        name: 'RSA-OAEP',
      ),
      await _rsaCryptoKeyFromPrivateKey(
        keyPair.privateKey, 
        name: 'RSA-OAEP',
        hashName: 'SHA-256',
        modulusLength: modulusLength,
        usage: 'decrypt',
      ),
      _jsArrayBufferFrom(plainText),
    ),
  );
  return Uint8List.view(byteBuffer);
}

Future<Signature> rsaPssSign(
  List<int> message,
  KeyPair keyPair, {
  @required int saltLength,
  @required String hashName,
}) async {
  final byteBuffer = await js.promiseToFuture(web_crypto.sign(
    web_crypto.RsaPssParams(
      name: 'RSA-PSS',
      saltLength: saltLength,
    ),
    await _rsaCryptoKeyFromPrivateKey(
      keyPair.privateKey,
      name: 'RSA-PSS',
      hashName: hashName,
      usage: 'sign',
    ),
    _jsArrayBufferFrom(message),
  ));
  return Signature(
    Uint8List.view(byteBuffer),
    publicKey: keyPair.publicKey,
  );
}

Future<bool> rsaPssVerify(
  List<int> input,
  Signature signature, {
  @required int saltLength,
  @required String hashName,
}) async {
  return js.promiseToFuture<bool>(web_crypto.verify(
    web_crypto.RsaPssParams(
      name: 'RSA-PSS',
      saltLength: saltLength,
    ),
    await _rsaCryptoKeyFromPublicKey(
      signature.publicKey,
      name: 'RSA-PSS',
      hashName: hashName,
      usage: 'verify',
    ),
    _jsArrayBufferFrom(signature.bytes),
    _jsArrayBufferFrom(input),
  ));
}

Future<Signature> rsaSsaPkcs1v15Sign(
  List<int> input,
  KeyPair keyPair, {
  @required String hashName,
}) async {
  final byteBuffer = await js.promiseToFuture(web_crypto.sign(
    'RSASSA-PKCS1-v1_5',
    await _rsaCryptoKeyFromPrivateKey(
      keyPair.privateKey,
      name: 'RSASSA-PKCS1-v1_5',
      hashName: hashName,
      usage: 'sign',
    ),
    _jsArrayBufferFrom(input),
  ));
  return Signature(
    Uint8List.view(byteBuffer),
    publicKey: keyPair.publicKey,
  );
}

Future<bool> rsaSsaPkcs1v15Verify(
  List<int> input,
  Signature signature, {
  @required String hashName,
}) async {
  return js.promiseToFuture<bool>(web_crypto.verify(
    'RSASSA-PKCS1-v1_5',
    await _rsaCryptoKeyFromPublicKey(
      signature.publicKey,
      name: 'RSASSA-PKCS1-v1_5',
      hashName: hashName,
      usage: 'verify',
    ),
    _jsArrayBufferFrom(signature.bytes),
    _jsArrayBufferFrom(input),
  ));
}

Future<web_crypto.CryptoKey> _rsaCryptoKeyFromPrivateKey(
  PrivateKey privateKey, {
  @required String name,
  @required String hashName,
  @required String usage,
  int modulusLength,
}) async {
  // Is it cached?
  final cachedValue = privateKey.cachedValues[usage];
  if (cachedValue != null) {
    return cachedValue;
  }

  // Import JWK key
  var jsCryptoKey;
  if (privateKey is RsaJwkPrivateKey) {
    final jwkPrivateKey = privateKey;
    jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: _base64UrlEncode(jwkPrivateKey.n),
          e: _base64UrlEncode(jwkPrivateKey.e),
          p: _base64UrlEncode(jwkPrivateKey.p),
          d: _base64UrlEncode(jwkPrivateKey.d),
          q: _base64UrlEncode(jwkPrivateKey.q),
          dp: _base64UrlEncode(jwkPrivateKey.dp),
          dq: _base64UrlEncode(jwkPrivateKey.dq),
          qi: _base64UrlEncode(jwkPrivateKey.qi),
        ),
        web_crypto.RsaHashedImportParams(
          name: name,
          hash: hashName,
        ),
        false,
        [usage],
      ),
    );
  } else if (privateKey is PEMPrivateKey) {
    assert(usage != 'encrypt' || modulusLength is int);

    jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'pkcs8',
        _jsArrayBufferFrom(privateKey.bytes),
        web_crypto.RsaHashedImportParams(
          name: name,
          hash: hashName,
          modulusLength: modulusLength,
          publicExponent: _jsArrayBufferFrom([1, 0, 1]),
        ),
        false,
        [usage],
      ),
    );
  }

  // Cache
  privateKey.cachedValues[usage] = jsCryptoKey;

  return jsCryptoKey;
}

Future<web_crypto.CryptoKey> _rsaCryptoKeyFromPublicKey(
  PublicKey publicKey, {
  @required String name,
  @required String hashName,
  @required String usage,
}) async {
  // Is it cached?
  final cachedValue = publicKey.cachedValues[usage];
  if (cachedValue != null) {
    return cachedValue;
  }

  var jsCryptoKey;

  if (publicKey is RsaJwkPublicKey) {
    final jwkPrivateKey = publicKey;
    jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'jwk',
        web_crypto.Jwk(
          kty: 'RSA',
          n: _base64UrlEncode(jwkPrivateKey.n),
          e: _base64UrlEncode(jwkPrivateKey.e),
        ),
        web_crypto.RsaHashedImportParams(
          name: name,
          hash: hashName,
        ),
        false,
        [usage],
      ),
    );
  } else if (publicKey is PEMPublicKey) {
    jsCryptoKey = js.promiseToFuture<web_crypto.CryptoKey>(
      web_crypto.importKey(
        'spki',
        _jsArrayBufferFrom(publicKey.bytes),
        web_crypto.RsaHashedImportParams(
          name: name,
          hash: hashName,
        ),
        false,
        [usage],
      ),
    );
  }

  // Cache
  publicKey.cachedValues[usage] = jsCryptoKey;

  return jsCryptoKey;
}