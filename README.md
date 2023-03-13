# split-crypt

Split files into chunks and encrypt them. Then decrypt them and combine them again.

## Goals

- Files should be split and combined for storage in environments with a maximum file size
- Folder structure and names of original files should be concealed in encrypted data
- Partial updates of encrypted set of files should be possible without re-encrypting everything
- Encrypting files should be possible without the use of a passphrase

## Requirements

This library uses new Node.js features, and requires version 16+ of Node.js.

## Usage

This library consists primarily of `crypt.js` which has the exports `init`, `encrypt`, `decrypt`, and `clean`.

It also contains helper utilities in `pass.js` which has the exports `get_pass` and `confirm_pass`.

### Initializing a new encrypted file store

```js
import { init } from './crypt.js';
import { confirm_pass } from './pass.js';

init({
	crypt: '/path/to/directory/to/initialize',
	cipher: 'aes-256-cbc',
	hash: 'sha512',
	hmac: 32,
	rsa: 2048,
	split: 33554432,
	passphrase: await confirm_pass(
		'Enter passphrase: ',
		'Confirm passphrase: ',
		'Passphrases do not match.',
	),
});
```

`init` expects to be passed:

- `crypt` - the directory to initialize as the encrypted file store
- `cipher` - the cipher to use for the (symmetric) encryption of data
- `hash` - the hash algorithm to use for file contents and names
- `hmac` - the number of bytes in the HMAC key to use
- `rsa` - the number of bits in the modulus of the (asymmetric) key pairs
- `split` - the number of bytes to split files into before encrypting
- `passphrase` - a string used to encrypt the private key on disk

### Updating encrypted file store with new and changed files

```js
import { encrypt } from './crypt.js';

const response = await encrypt({
	plain: '/path/to/plain/directory',
	crypt: '/path/to/encrypted/directory',
	cache: '/path/to/cache/file',
	filter: (path) => some_logic(path),
});

console.log(response);
```

`encrypt` expects to be passed:

- `plain` - the directory containing the original, unencrypted files
- `crypt` - the directory containing the encrypted file store to update
- `cache` - the path of the file to maintain various hash information
- `filter` (optional) - a function that is passed a path (the portion after `plain`) and returns whether the given file should be included in the encrypted file store
- `passphrase` (optional) - if passed, also delete unused `-data` files and reuse symmetric encryption parameters on renamed input files so the resultant encrypted files are also effectively renamed

### Updating decrypted file store with new and changed files

```js
import { decrypt } from './crypt.js';
import { get_pass } from './pass.js';

const response = await decrypt({
	crypt: '/path/to/encrypted/directory',
	plain: '/path/to/decrypted/directory',
	cache: '/path/to/cache/file',
	filter: (path) => some_logic(path),
	passphrase: await get_pass('Enter passphrase: '),
});

console.log(response);
```

`decrypt` expects to be passed:

- `crypt` - the directory containing the encrypted file store to decrypt
- `plain` - the destination directory for the decrypted files
- `cache` - the path of the file to maintain various hash information
- `filter` (optional) - a function that is passed a path (the portion after `plain`) and returns whether the given file should be decrypted from the encrypted file store, including whether it should be deleted if it does not exist in the store
- `passphrase` - the passphrase for the private key

### Cleaning unused data files in an encrypted file store

```js
import { clean } from './crypt.js';
import { get_pass } from './pass.js';

const response = await clean({
	crypt: '/path/to/encrypted/directory',
	passphrase: await get_pass('Enter passphrase: '),
});

console.log(response);
```

`clean` expects to be passed:

- `crypt` - the directory containing the encrypted file store to clean
- `passphrase` - the passphrase for the private key

## License

[MIT](LICENSE)
