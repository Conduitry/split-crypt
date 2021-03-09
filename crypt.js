const CACHE_PATH = __dirname + '/cache';
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-cbc';
const DEFAULT_HASH_ALGORITHM = 'sha512';
const HMAC_KEY_LENGTH = 32;
const RSA_KEY_BITS = 2048;
const STREAM_CONCURRENCY = 8;

const crypto = require('crypto');
const fs = require('fs');
const path_ = require('path');
const v8 = require('v8');

function init({ crypt: crypt_dir, cipher: cipher_algorithm = DEFAULT_CIPHER_ALGORITHM, hash: hash_algorithm = DEFAULT_HASH_ALGORITHM, split: split_size, passphrase }) {
	fs.mkdirSync(crypt_dir, { recursive: true });
	fs.writeFileSync(crypt_dir + '/!meta.dat', v8.serialize({ cipher_algorithm, hash_algorithm, split_size, hmac_key: crypto.randomBytes(HMAC_KEY_LENGTH) }));
	const pair = crypto.generateKeyPairSync('rsa', { modulusLength: RSA_KEY_BITS });
	fs.writeFileSync(crypt_dir + '/!public.key', pair.publicKey.export({ type: 'spki', format: 'pem' }));
	fs.writeFileSync(crypt_dir + '/!private.key', pair.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: cipher_algorithm, passphrase }));
}

function get_info(crypt_dir, passphrase) {
	const info = v8.deserialize(fs.readFileSync(crypt_dir + '/!meta.dat'));
	info.public_key = crypto.createPublicKey(fs.readFileSync(crypt_dir + '/!public.key'));
	info.index = new Map();
	for (const dirent of fs.readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('.index')) {
			info.index.set(dirent.name.slice(0, -6), v8.deserialize(fs.readFileSync(crypt_dir + '/' + dirent.name)));
		}
	}
	if (passphrase != null) {
		info.private_key = crypto.createPrivateKey({ key: fs.readFileSync(crypt_dir + '/!private.key'), passphrase });
	}
	return info;
}

async function get_plain_index(plain_dir, hash_algorithm, filter) {
	let cache;
	try {
		cache = v8.deserialize(fs.readFileSync(CACHE_PATH));
	} catch {
		cache = new Map();
	}
	const plain_index = new Map();
	const pending = [plain_dir];
	while (pending.length) {
		const dir = pending.shift();
		for (const name of fs.readdirSync(dir)) {
			const path = dir + '/' + name;
			const stats = fs.statSync(path);
			if (stats.isFile()) {
				if (!filter || filter(path.slice(plain_dir.length + 1))) {
					const key = path + ':' + hash_algorithm;
					if (cache.has(key) && cache.get(key).size === stats.size && cache.get(key).mtimeMs === stats.mtimeMs) {
						plain_index.set(path.slice(plain_dir.length + 1), { size: stats.size, hash: cache.get(key).hash });
					} else {
						const hash = await new Promise((res) => {
							const hash = crypto.createHash(hash_algorithm);
							fs.createReadStream(path)
								.once('end', () => res(hash.digest()))
								.pipe(hash);
						});
						cache.set(key, { size: stats.size, mtimeMs: stats.mtimeMs, hash });
						plain_index.set(path.slice(plain_dir.length + 1), { size: stats.size, hash });
					}
				}
			} else if (stats.isDirectory()) {
				pending.push(path);
			}
		}
	}
	fs.writeFileSync(CACHE_PATH, v8.serialize(cache));
	return plain_index;
}

function get_crypt_filename(info, path, start) {
	return (
		crypto
			.createHmac(info.hash_algorithm, info.hmac_key)
			.update(path + '@' + start)
			.digest('base64url') + '.data'
	);
}

function make_stream_queue() {
	const queue = [];
	let active = 0;
	let resolve;
	function run() {
		if (active === 0 && queue.length === 0) {
			resolve();
		}
		if (active < STREAM_CONCURRENCY && queue.length > 0) {
			active++;
			queue
				.shift()()
				.once('finish', () => {
					active--;
					queueMicrotask(run);
				});
		}
	}
	const promise = new Promise((res) => (resolve = res));
	return {
		promise,
		enqueue(func) {
			queue.push(func);
			queueMicrotask(run);
		},
	};
}

async function encrypt({ plain: plain_dir, crypt: crypt_dir, filter }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	// READ CRYPT INDEX
	const info = get_info(crypt_dir);
	const { keyLength, ivLength } = crypto.getCipherInfo(info.cipher_algorithm);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	const path_hmac_lookup = new Map();
	for (const [path] of plain_index) {
		path_hmac_lookup.set(crypto.createHmac(info.hash_algorithm, info.hmac_key).update(path).digest('base64url'), path);
	}
	// DELETE INDEXES FOR MISSING FILES
	for (const path_hmac of info.index.keys()) {
		if (!path_hmac_lookup.has(path_hmac)) {
			deleted.add(path_hmac + '.index');
			fs.unlinkSync(crypt_dir + '/' + path_hmac + '.index');
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path_hmac, path] of path_hmac_lookup) {
		const { size, hash } = plain_index.get(path);
		const hash_hmac = crypto.createHmac(info.hash_algorithm, info.hmac_key).update(hash).digest();
		if (!info.index.has(path_hmac)) {
			added.add(path);
		} else if (Buffer.compare(info.index.get(path_hmac)[0], hash_hmac)) {
			updated.add(path);
		} else {
			continue;
		}
		const key = crypto.randomBytes(keyLength);
		const iv = crypto.randomBytes(ivLength);
		const cipher = crypto.createCipheriv(info.cipher_algorithm, key, iv);
		fs.writeFileSync(
			crypt_dir + '/' + path_hmac + '.index',
			v8.serialize([hash_hmac, crypto.publicEncrypt(info.public_key, key), crypto.publicEncrypt(info.public_key, iv), Buffer.concat([cipher.update(path), cipher.final()])]),
		);
		for (let start = 0; ; start += info.split_size) {
			try {
				fs.unlinkSync(crypt_dir + '/' + get_crypt_filename(info, path, start));
			} catch {
				break;
			}
		}
		for (let start = 0; start < size; start += info.split_size) {
			const cipher = crypto.createCipheriv(info.cipher_algorithm, key, iv);
			stream_queue.enqueue(() =>
				fs
					.createReadStream(plain_dir + '/' + path, { start, end: Math.min(start + info.split_size - 1, size - 1) })
					.pipe(cipher)
					.pipe(fs.createWriteStream(crypt_dir + '/' + get_crypt_filename(info, path, start))),
			);
		}
	}
	if (added.size > 0 || updated.size > 0) {
		await stream_queue.promise;
	}
	return { added, deleted, updated };
}

function clean({ crypt: crypt_dir, passphrase }) {
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	// GET CRYPT FILES
	const crypt_filenames = new Set();
	for (const dirent of fs.readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('.data')) {
			crypt_filenames.add(dirent.name);
		}
	}
	// REMOVE ALL FILES REFERRED TO BY AN INDEX
	for (const item of info.index.values()) {
		const key = crypto.privateDecrypt(info.private_key, item[1]);
		const iv = crypto.privateDecrypt(info.private_key, item[2]);
		const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
		const path = Buffer.concat([decipher.update(item[3]), decipher.final()]).toString();
		for (let start = 0; ; start += info.split_size) {
			const crypt_filename = get_crypt_filename(info, path, start);
			if (crypt_filenames.has(crypt_filename)) {
				crypt_filenames.delete(crypt_filename);
			} else {
				break;
			}
		}
	}
	// DELETE UNUSED CRYPT FILES
	for (const crypt_filename of crypt_filenames) {
		fs.unlinkSync(crypt_dir + '/' + crypt_filename);
	}
	return { deleted: crypt_filenames };
}

async function decrypt({ plain: plain_dir, crypt: crypt_dir, filter, passphrase }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	fs.mkdirSync(plain_dir, { recursive: true });
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	// DELETE MISSING FILES
	const path_hmac_lookup = new Map();
	for (const [path] of plain_index) {
		const path_hmac = crypto.createHmac(info.hash_algorithm, info.hmac_key).update(path).digest('base64url');
		if (info.index.has(path_hmac)) {
			path_hmac_lookup.set(path_hmac, path);
		} else {
			deleted.add(path);
			fs.unlinkSync(plain_dir + '/' + path);
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path_hmac, item] of info.index) {
		let target = updated;
		if (!path_hmac_lookup.has(path_hmac)) {
			target = added;
		} else if (
			!Buffer.compare(
				crypto
					.createHmac(info.hash_algorithm, info.hmac_key)
					.update(plain_index.get(path_hmac_lookup.get(path_hmac)).hash)
					.digest(),
				item[0],
			)
		) {
			continue;
		}
		const key = crypto.privateDecrypt(info.private_key, item[1]);
		const iv = crypto.privateDecrypt(info.private_key, item[2]);
		const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
		const path = Buffer.concat([decipher.update(item[3]), decipher.final()]).toString();
		target.add(path);
		fs.mkdirSync(plain_dir + '/' + path_.dirname(path), { recursive: true });
		fs.writeFileSync(plain_dir + '/' + path, Buffer.alloc(0));
		for (let start = 0; ; start += info.split_size) {
			const file = crypt_dir + '/' + get_crypt_filename(info, path, start);
			try {
				fs.accessSync(file);
			} catch {
				break;
			}
			const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
			stream_queue.enqueue(() =>
				fs
					.createReadStream(file)
					.pipe(decipher)
					.pipe(fs.createWriteStream(plain_dir + '/' + path, { flags: 'r+', start })),
			);
		}
	}
	if (added.size > 0 || updated.size > 0) {
		await stream_queue.promise;
	}
	return { added, deleted, updated };
}

module.exports = { init, encrypt, clean, decrypt };
