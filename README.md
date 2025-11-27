# static-encrypt-passkey

A tool to encrypt and decrypt any static content **using passkeys**.

Use [static-encrypt](https://github.com/ardislu/static-encrypt) to encrypt using a password instead of a passkey.

Code repository mirrors: [GitHub](https://github.com/ardislu/static-encrypt-passkey), [Codeberg](https://codeberg.org/ardislu/static-encrypt-passkey), [git.ardis.lu](https://git.ardis.lu/static-encrypt-passkey)

## Why `108117.xyz`?

The Web Authentication API ties passkeys to a "relying party," which is typically the domain. A standalone domain reduces the risk of mixing single-use encryption passkeys with "real" passkeys used for other domains.

The domain name was picked to be within the cheap [`.xyz` 1.111B Class](https://gen.xyz/1111b) and is equal to:

```javascript
[...new TextEncoder().encode('lu')].join('');
// "108117" 
```
