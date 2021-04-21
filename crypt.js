const CACHE_PATH = dirname(fileURLToPath(import.meta.url)) + '/cache';
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-cbc';
const DEFAULT_HASH_ALGORITHM = 'sha512';
const DEFAULT_SPLIT_SIZE = 33554432;
const HMAC_KEY_LENGTH = 32;
const RSA_KEY_BITS = 2048;
const STREAM_CONCURRENCY = 8;

import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	createPrivateKey,
	createPublicKey,
	generateKeyPairSync,
	getCipherInfo,
	privateDecrypt,
	publicEncrypt,
	randomBytes,
} from 'crypto';
import {
	accessSync,
	createReadStream,
	createWriteStream,
	mkdirSync,
	readdirSync,
	readFileSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from 'fs';
import { dirname } from 'path';
import { fileURLToPath } from 'url';
import { deserialize, serialize } from 'v8';

export function init({
	crypt: crypt_dir,
	cipher: cipher_algorithm = DEFAULT_CIPHER_ALGORITHM,
	hash: hash_algorithm = DEFAULT_HASH_ALGORITHM,
	split: split_size = DEFAULT_SPLIT_SIZE,
	passphrase,
}) {
	mkdirSync(crypt_dir, { recursive: true });
	writeFileSync(
		crypt_dir + '/info',
		cipher_algorithm +
			'\n' +
			hash_algorithm +
			'\n' +
			split_size +
			'\n' +
			randomBytes(HMAC_KEY_LENGTH).toString('base64url') +
			'\n',
	);
	const pair = generateKeyPairSync('rsa', { modulusLength: RSA_KEY_BITS });
	writeFileSync(crypt_dir + '/public', pair.publicKey.export({ type: 'spki', format: 'pem' }));
	writeFileSync(
		crypt_dir + '/private',
		pair.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: cipher_algorithm, passphrase }),
	);
}

function get_info(crypt_dir, passphrase) {
	const s = readFileSync(crypt_dir + '/info', 'ascii').match(/\S+/g);
	const info = {
		cipher_algorithm: s[0],
		hash_algorithm: s[1],
		split_size: +s[2],
		hmac_key: Buffer.from(s[3], 'base64url'),
		public_key: createPublicKey(readFileSync(crypt_dir + '/public')),
		index: new Map(),
	};
	for (const dirent of readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('-index')) {
			const s = readFileSync(crypt_dir + '/' + dirent.name, 'ascii').match(/\S+/g);
			info.index.set(dirent.name.slice(0, -6), {
				hash_hmac: Buffer.from(s[0], 'base64url'),
				key: Buffer.from(s[1], 'base64url'),
				iv: Buffer.from(s[2], 'base64url'),
				path: Buffer.from(s[3], 'base64url'),
			});
		}
	}
	if (passphrase != null) {
		info.private_key = createPrivateKey({
			key: readFileSync(crypt_dir + '/private'),
			passphrase,
		});
	}
	return info;
}

async function get_plain_index(plain_dir, hash_algorithm, filter) {
	let cache;
	try {
		cache = deserialize(readFileSync(CACHE_PATH));
	} catch {
		cache = new Map();
	}
	const plain_index = new Map();
	const pending = [plain_dir];
	const stream_queue = make_stream_queue();
	while (pending.length) {
		const dir = pending.shift();
		for (const name of readdirSync(dir)) {
			const path = dir + '/' + name;
			const stats = statSync(path);
			if (stats.isFile()) {
				if (!filter || filter(path.slice(plain_dir.length + 1))) {
					const key = path + ':' + hash_algorithm;
					if (
						cache.has(key) &&
						cache.get(key).size === stats.size &&
						cache.get(key).mtimeMs === stats.mtimeMs
					) {
						plain_index.set(path.slice(plain_dir.length + 1), {
							size: stats.size,
							hash: cache.get(key).hash,
						});
					} else {
						stream_queue.add(() =>
							createReadStream(path)
								.pipe(createHash(hash_algorithm))
								.once('readable', function () {
									const hash = this.read();
									cache.set(key, { size: stats.size, mtimeMs: stats.mtimeMs, hash });
									plain_index.set(path.slice(plain_dir.length + 1), { size: stats.size, hash });
								}),
						);
					}
				}
			} else if (stats.isDirectory()) {
				pending.push(path);
			}
		}
	}
	await stream_queue.done();
	writeFileSync(CACHE_PATH, serialize(cache));
	return plain_index;
}

function get_crypt_filename(info, path, start) {
	return (
		createHmac(info.hash_algorithm, info.hmac_key)
			.update(path + '@' + start)
			.digest('base64url') + '-data'
	);
}

function make_stream_queue() {
	const queue = [];
	let active = 0;
	let resolve;
	function run() {
		if (active === 0 && queue.length === 0 && resolve) {
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
	return {
		add(func) {
			queue.push(func);
			queueMicrotask(run);
		},
		done() {
			return active === 0 && queue.length === 0
				? Promise.resolve()
				: new Promise((res) => (resolve = res));
		},
	};
}

export async function encrypt({ plain: plain_dir, crypt: crypt_dir, filter }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	// READ CRYPT INDEX
	const info = get_info(crypt_dir);
	const { keyLength, ivLength } = getCipherInfo(info.cipher_algorithm);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	const path_hmac_lookup = new Map();
	for (const path of plain_index.keys()) {
		path_hmac_lookup.set(
			createHmac(info.hash_algorithm, info.hmac_key).update(path).digest('base64url'),
			path,
		);
	}
	// DELETE INDEXES FOR MISSING FILES
	for (const path_hmac of info.index.keys()) {
		if (!path_hmac_lookup.has(path_hmac)) {
			deleted.add(path_hmac + '-index');
			unlinkSync(crypt_dir + '/' + path_hmac + '-index');
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path_hmac, path] of path_hmac_lookup) {
		const { size, hash } = plain_index.get(path);
		const hash_hmac = createHmac(info.hash_algorithm, info.hmac_key).update(hash).digest();
		if (!info.index.has(path_hmac)) {
			added.add(path);
		} else if (Buffer.compare(info.index.get(path_hmac).hash_hmac, hash_hmac)) {
			updated.add(path);
		} else {
			continue;
		}
		const key = randomBytes(keyLength);
		const iv = randomBytes(ivLength);
		const cipher = createCipheriv(info.cipher_algorithm, key, iv);
		writeFileSync(
			crypt_dir + '/' + path_hmac + '-index',
			hash_hmac.toString('base64url') +
				'\n' +
				publicEncrypt(info.public_key, key).toString('base64url') +
				'\n' +
				publicEncrypt(info.public_key, iv).toString('base64url') +
				'\n' +
				Buffer.concat([cipher.update(path), cipher.final()]).toString('base64url') +
				'\n',
		);
		for (let start = 0; ; start += info.split_size) {
			if (start < size) {
				stream_queue.add(() =>
					createReadStream(plain_dir + '/' + path, {
						start,
						end: Math.min(start + info.split_size - 1, size - 1),
					})
						.pipe(createCipheriv(info.cipher_algorithm, key, iv))
						.pipe(createWriteStream(crypt_dir + '/' + get_crypt_filename(info, path, start))),
				);
			} else {
				try {
					unlinkSync(crypt_dir + '/' + get_crypt_filename(info, path, start));
				} catch {
					break;
				}
			}
		}
	}
	await stream_queue.done();
	return { added, deleted, updated };
}

export function clean({ crypt: crypt_dir, passphrase }) {
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	// GET CRYPT FILES
	const crypt_filenames = new Set();
	for (const dirent of readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('-data')) {
			crypt_filenames.add(dirent.name);
		}
	}
	// SKIP ALL FILES REFERRED TO BY AN INDEX
	for (const item of info.index.values()) {
		const key = privateDecrypt(info.private_key, item.key);
		const iv = privateDecrypt(info.private_key, item.iv);
		const decipher = createDecipheriv(info.cipher_algorithm, key, iv);
		const path = Buffer.concat([decipher.update(item.path), decipher.final()]).toString();
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
		unlinkSync(crypt_dir + '/' + crypt_filename);
	}
	return { deleted: crypt_filenames };
}

export async function decrypt({ plain: plain_dir, crypt: crypt_dir, filter, passphrase }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	mkdirSync(plain_dir, { recursive: true });
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	// DELETE MISSING FILES
	const path_hmac_lookup = new Map();
	for (const path of plain_index.keys()) {
		const path_hmac = createHmac(info.hash_algorithm, info.hmac_key)
			.update(path)
			.digest('base64url');
		if (info.index.has(path_hmac)) {
			path_hmac_lookup.set(path_hmac, path);
		} else {
			deleted.add(path);
			unlinkSync(plain_dir + '/' + path);
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path_hmac, item] of info.index) {
		let target;
		if (!path_hmac_lookup.has(path_hmac)) {
			target = added;
		} else if (
			Buffer.compare(
				createHmac(info.hash_algorithm, info.hmac_key)
					.update(plain_index.get(path_hmac_lookup.get(path_hmac)).hash)
					.digest(),
				item.hash_hmac,
			)
		) {
			target = updated;
		} else {
			continue;
		}
		const key = privateDecrypt(info.private_key, item.key);
		const iv = privateDecrypt(info.private_key, item.iv);
		const decipher = createDecipheriv(info.cipher_algorithm, key, iv);
		const path = Buffer.concat([decipher.update(item.path), decipher.final()]).toString();
		target.add(path);
		mkdirSync(plain_dir + '/' + dirname(path), { recursive: true });
		writeFileSync(plain_dir + '/' + path, Buffer.alloc(0));
		for (let start = 0; ; start += info.split_size) {
			const file = crypt_dir + '/' + get_crypt_filename(info, path, start);
			try {
				accessSync(file);
			} catch {
				break;
			}
			stream_queue.add(() =>
				createReadStream(file)
					.pipe(createDecipheriv(info.cipher_algorithm, key, iv))
					.pipe(createWriteStream(plain_dir + '/' + path, { flags: 'r+', start })),
			);
		}
	}
	await stream_queue.done();
	return { added, deleted, updated };
}
