/**
 * Create a new resident passkey and get a pseudo-random value produced from the passkey PRF extension.
 * 
 * If the passkey does not return a PRF value after creation, try to sign in immediately after passkey creation
 * and get the PRF value from the sign in flow.
 * @see {@link https://www.w3.org/TR/webauthn-3/#prf-extension}
 * @returns {Promise<ArrayBuffer&{byteLength:32}>} A 32 byte long `ArrayBuffer` containing a pseudo-random
 * value produced from the passkey PRF extension.
 */
async function createPrf() {
  return navigator.credentials.create({
    publicKey: {
      rp: { name: '' },
      user: { id: new ArrayBuffer(1), name: crypto.randomUUID(), displayName: '' }, // Windows Hello requires non-empty id; Yubikey requires non-empty name
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      extensions: { prf: { eval: { first: new ArrayBuffer(0) } } },
      challenge: new ArrayBuffer(0),
      authenticatorSelection: { residentKey: 'required' } // Resident key is required because there is no server to store c.rawId
    }
  }).then(c => c.getClientExtensionResults().prf?.results?.first ?? getPrf()); // Yubikey does not return PRF on creation, workaround is sign in immediately after creation
}

/**
 * Request a "sign in" with a passkey created previously, if it exists. This function will return the same
 * pseudo-random value produced during the passkey creation function.
 * @see {@link https://www.w3.org/TR/webauthn-3/#prf-extension}
 * @returns {Promise<ArrayBuffer&{byteLength:32}>} A 32 byte long `ArrayBuffer` containing a pseudo-random
 * value produced from the passkey PRF extension.
 */
async function getPrf() {
  return navigator.credentials.get({
    publicKey: {
      extensions: { prf: { eval: { first: new ArrayBuffer(0) } } },
      challenge: new ArrayBuffer(0)
    }
  }).then(c => c.getClientExtensionResults().prf.results.first);
}

/**
 * Create a `CryptoKey` from a high-entropy random value using the HKDF algorithm.
 * @param {ArrayBuffer|ArrayBufferView<ArrayBufferLike>} rand A high-entropy random value.
 * @param {ArrayBuffer|ArrayBufferView<ArrayBufferLike>} salt A cryptographic salt value.
 * @param {ArrayBuffer|ArrayBufferView<ArrayBufferLike>} info Additional contextual information.
 * @returns {Promise<CryptoKey>} A `CryptoKey` that can be used for `"encrypt"` or `"decrypt"`.
 */
async function getKey(rand, salt, info) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    rand,
    'HKDF',
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-512',
      salt,
      info
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return key;
}

/**
 * Encrypt a `string` by creating a new passkey then using the passkey's PRF extension to generate a
 * HKDF key and encrypt the `string`. The `salt` and `iv` values are embedded (in plaintext)
 * alongside the ciphertext.
 * @param {string} plaintext An unencrypted value to encrypt using a new passkey.
 * @returns {Promise<string>} The encrypted plaintext (i.e., ciphertext) with `salt` and `iv` values
 * in base64.
 */
export async function encrypt(plaintext) {
  // Generate all required random values
  const salt = crypto.getRandomValues(new Uint8Array(64)); // For HKDF
  const iv = crypto.getRandomValues(new Uint8Array(12)); // For AES-GCM

  // Prepare non-crypto inputs
  const encoder = new TextEncoder();
  const encodedPlaintext = encoder.encode(plaintext);
  const info = encoder.encode('https://github.com/ardislu/static-encrypt-passkey');

  // Pad ciphertext so the final buffer length is a multiple of 3, to remove base64 padding. Not cryptographically
  // significant, just for aesthetics. +16 assumes ciphertext includes a 128 bit AES-GCM authentication tag.
  const p = 3 - ((salt.byteLength + iv.byteLength + encodedPlaintext.byteLength + 16) % 3);
  const paddedPlaintext = new Uint8Array(encodedPlaintext.byteLength + p);
  paddedPlaintext.set([p]); // Offset to discard on decode
  paddedPlaintext.set(encodedPlaintext, p); // Gap filled with zero bytes, e.g. [3, 0, 0, ...encodedPlaintext]

  const prf = await createPrf();
  const key = await getKey(prf, salt, info);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    paddedPlaintext
  ));

  const buffer = new Uint8Array(salt.byteLength + iv.byteLength + ciphertext.byteLength);
  buffer.set(salt);
  buffer.set(iv, salt.byteLength);
  buffer.set(ciphertext, salt.byteLength + iv.byteLength);
  let binary = '';
  for (let i = 0; i < buffer.byteLength; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  const content = btoa(binary);

  return content;
}

/**
 * Decrypt a `string` that has been encrypted with a passkey. Assuming the required `salt` and `iv`
 * values are embedded alongside the ciphertext.
 * @param {string} content A base64-encoded ciphertext and required cryptographic values.
 * @returns {Promise<string>} The decrypted plaintext.
 * @throws {OperationError} Decryption operation failed.
 */
export async function decrypt(content) {
  // Extract random values
  const buffer = Uint8Array.from(atob(content), c => c.charCodeAt(0));
  const salt = buffer.slice(0, 64); // For HKDF
  const iv = buffer.slice(64, 76); // For AES-GCM
  const ciphertext = buffer.slice(76);

  // Prepare non-crypto inputs
  const info = new TextEncoder().encode('https://github.com/ardislu/static-encrypt-passkey');

  const prf = await getPrf();
  const key = await getKey(prf, salt, info);
  const encodedPlaintext = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  ));
  const unpaddedPlaintext = encodedPlaintext.slice(encodedPlaintext[0]);

  const plaintext = new TextDecoder().decode(unpaddedPlaintext);

  return plaintext;
}