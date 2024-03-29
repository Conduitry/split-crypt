import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import { cpus } from 'node:os';
import { dirname } from 'node:path';
import { deserialize, serialize } from 'node:v8';

const num_processors = cpus().length;

export function init({
	crypt: crypt_dir,
	cipher: cipher_algorithm,
	hash: hash_algorithm,
	hmac: hmac_bytes,
	rsa: rsa_key_bits,
	split: split_size,
	passphrase,
}) {
	fs.mkdirSync(crypt_dir, { recursive: true });
	fs.writeFileSync(
		crypt_dir + '/info',
		cipher_algorithm +
			'\n' +
			hash_algorithm +
			'\n' +
			split_size +
			'\n' +
			crypto.randomBytes(hmac_bytes).toString('base64url') +
			'\n',
	);
	const pair = crypto.generateKeyPairSync('rsa', { modulusLength: rsa_key_bits });
	fs.writeFileSync(crypt_dir + '/public', pair.publicKey.export({ type: 'spki', format: 'pem' }));
	fs.writeFileSync(
		crypt_dir + '/private',
		pair.privateKey.export({ type: 'pkcs8', format: 'pem', cipher: cipher_algorithm, passphrase }),
	);
}

function get_info(crypt_dir, passphrase) {
	const s = fs.readFileSync(crypt_dir + '/info', 'ascii').match(/\S+/g);
	const info = {
		cipher_algorithm: s[0],
		hash_algorithm: s[1],
		split_size: +s[2],
		hmac_key: Buffer.from(s[3], 'base64url'),
		public_key: crypto.createPublicKey(fs.readFileSync(crypt_dir + '/public')),
		index: new Map(),
	};
	for (const dirent of fs.readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('-index')) {
			const s = fs.readFileSync(crypt_dir + '/' + dirent.name, 'ascii').match(/\S+/g);
			info.index.set(dirent.name.slice(0, -6), {
				hash_hmac: Buffer.from(s[0], 'base64url'),
				key: Buffer.from(s[1], 'base64url'),
				iv: Buffer.from(s[2], 'base64url'),
				path: Buffer.from(s[3], 'base64url'),
			});
		}
	}
	if (passphrase != null) {
		info.private_key = crypto.createPrivateKey({
			key: fs.readFileSync(crypt_dir + '/private'),
			passphrase,
		});
	}
	return info;
}

async function get_plain_index(plain_dir, hash_algorithm, filter, cache_path) {
	let cache = new Map();
	if (cache_path) {
		try {
			cache = deserialize(fs.readFileSync(cache_path));
		} catch {}
	}
	const plain_index = new Map();
	const pending = [plain_dir];
	const stream_queue = make_stream_queue();
	while (pending.length) {
		const dir = pending.shift();
		for (const name of fs.readdirSync(dir)) {
			const path = dir + '/' + name;
			const stats = fs.statSync(path);
			if (stats.isFile()) {
				if (!filter || filter(path.slice(plain_dir.length + 1))) {
					const key = path + ':' + hash_algorithm;
					if (cache.has(key) && cache.get(key).size === stats.size && cache.get(key).mtimeMs === stats.mtimeMs) {
						plain_index.set(path.slice(plain_dir.length + 1), {
							size: stats.size,
							hash: cache.get(key).hash,
						});
					} else {
						stream_queue.add(() =>
							fs
								.createReadStream(path)
								.pipe(crypto.createHash(hash_algorithm))
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
	if (cache_path) {
		fs.writeFileSync(cache_path, serialize(cache));
	}
	return plain_index;
}

function get_crypt_filename(info, path, start) {
	return (
		crypto
			.createHmac(info.hash_algorithm, info.hmac_key)
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
		if (active < num_processors && queue.length > 0) {
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
			return active === 0 && queue.length === 0 ? Promise.resolve() : new Promise((res) => (resolve = res));
		},
	};
}

export async function encrypt({ plain: plain_dir, crypt: crypt_dir, cache: cache_path, filter, passphrase }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	const { keyLength, ivLength } = crypto.getCipherInfo(info.cipher_algorithm);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter, cache_path);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	const path_hmac_lookup = new Map();
	for (const path of plain_index.keys()) {
		path_hmac_lookup.set(crypto.createHmac(info.hash_algorithm, info.hmac_key).update(path).digest('base64url'), path);
	}
	// DELETE INDEXES FOR MISSING FILES
	for (const [path_hmac, item] of info.index) {
		if (!path_hmac_lookup.has(path_hmac)) {
			deleted.add(path_hmac + '-index');
			fs.unlinkSync(crypt_dir + '/' + path_hmac + '-index');
			if (info.private_key) {
				const key = crypto.privateDecrypt(info.private_key, item.key);
				const iv = crypto.privateDecrypt(info.private_key, item.iv);
				const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
				const path = Buffer.concat([decipher.update(item.path), decipher.final()]).toString();
				for (let start = 0; ; start += info.split_size) {
					const crypt_filename = get_crypt_filename(info, path, start);
					try {
						fs.unlinkSync(crypt_dir + '/' + crypt_filename);
						deleted.add(crypt_filename);
					} catch {
						break;
					}
				}
			}
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path_hmac, path] of path_hmac_lookup) {
		const { size, hash } = plain_index.get(path);
		const hash_hmac = crypto.createHmac(info.hash_algorithm, info.hmac_key).update(hash).digest();
		if (!info.index.has(path_hmac)) {
			added.add(path);
		} else if (Buffer.compare(info.index.get(path_hmac).hash_hmac, hash_hmac)) {
			updated.add(path);
		} else {
			continue;
		}
		let key = crypto.randomBytes(keyLength);
		let iv = crypto.randomBytes(ivLength);
		if (info.private_key) {
			for (const item of info.index.values()) {
				if (Buffer.compare(item.hash_hmac, hash_hmac) === 0) {
					key = crypto.privateDecrypt(info.private_key, item.key);
					iv = crypto.privateDecrypt(info.private_key, item.iv);
					break;
				}
			}
		}
		const cipher = crypto.createCipheriv(info.cipher_algorithm, key, iv);
		fs.writeFileSync(
			crypt_dir + '/' + path_hmac + '-index',
			hash_hmac.toString('base64url') +
				'\n' +
				crypto.publicEncrypt(info.public_key, key).toString('base64url') +
				'\n' +
				crypto.publicEncrypt(info.public_key, iv).toString('base64url') +
				'\n' +
				Buffer.concat([cipher.update(path), cipher.final()]).toString('base64url') +
				'\n',
		);
		for (let start = 0; ; start += info.split_size) {
			if (start < size) {
				stream_queue.add(() =>
					fs
						.createReadStream(plain_dir + '/' + path, {
							start,
							end: Math.min(start + info.split_size - 1, size - 1),
						})
						.pipe(crypto.createCipheriv(info.cipher_algorithm, key, iv))
						.pipe(fs.createWriteStream(crypt_dir + '/' + get_crypt_filename(info, path, start))),
				);
			} else {
				try {
					fs.unlinkSync(crypt_dir + '/' + get_crypt_filename(info, path, start));
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
	for (const dirent of fs.readdirSync(crypt_dir, { withFileTypes: true })) {
		if (dirent.isFile() && dirent.name.endsWith('-data')) {
			crypt_filenames.add(dirent.name);
		}
	}
	// SKIP ALL FILES REFERRED TO BY AN INDEX
	for (const item of info.index.values()) {
		const key = crypto.privateDecrypt(info.private_key, item.key);
		const iv = crypto.privateDecrypt(info.private_key, item.iv);
		const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
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
		fs.unlinkSync(crypt_dir + '/' + crypt_filename);
	}
	return { deleted: crypt_filenames };
}

export async function decrypt({ crypt: crypt_dir, plain: plain_dir, cache: cache_path, filter, passphrase }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	fs.mkdirSync(plain_dir, { recursive: true });
	// READ CRYPT INDEX
	const info = get_info(crypt_dir, passphrase);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index(plain_dir, info.hash_algorithm, filter, cache_path);
	// CREATE INDEX OF PLAIN FILES AS THEY WILL APPEAR IN THE CRYPT INDEX
	// DELETE MISSING FILES
	const path_hmac_lookup = new Map();
	for (const path of plain_index.keys()) {
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
		let target;
		if (!path_hmac_lookup.has(path_hmac)) {
			target = added;
		} else if (
			Buffer.compare(
				crypto
					.createHmac(info.hash_algorithm, info.hmac_key)
					.update(plain_index.get(path_hmac_lookup.get(path_hmac)).hash)
					.digest(),
				item.hash_hmac,
			)
		) {
			target = updated;
		} else {
			continue;
		}
		const key = crypto.privateDecrypt(info.private_key, item.key);
		const iv = crypto.privateDecrypt(info.private_key, item.iv);
		const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
		const path = Buffer.concat([decipher.update(item.path), decipher.final()]).toString();
		target.add(path);
		fs.mkdirSync(plain_dir + '/' + dirname(path), { recursive: true });
		fs.writeFileSync(plain_dir + '/' + path, Buffer.alloc(0));
		for (let start = 0; ; start += info.split_size) {
			const file = crypt_dir + '/' + get_crypt_filename(info, path, start);
			try {
				fs.accessSync(file);
			} catch {
				break;
			}
			stream_queue.add(() =>
				fs
					.createReadStream(file)
					.pipe(crypto.createDecipheriv(info.cipher_algorithm, key, iv))
					.pipe(fs.createWriteStream(plain_dir + '/' + path, { flags: 'r+', start })),
			);
		}
	}
	await stream_queue.done();
	return { added, deleted, updated };
}
