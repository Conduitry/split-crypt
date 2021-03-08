const CACHE_PATH = __dirname + '/cache';
const DEFAULT_CIPHER_ALGORITHM = 'aes-256-cbc';
const DEFAULT_HASH_ALGORITHM = 'sha512';
const SALT_LENGTH = 32;
const STREAM_CONCURRENCY = 8;

const crypto = require('crypto');
const fs = require('fs');
const path_ = require('path');
const v8 = require('v8');

function make_info({ cipher_algorithm, hash_algorithm, split_size, password, index }) {
	const salt = crypto.randomBytes(SALT_LENGTH);
	const { keyLength, ivLength } = crypto.getCipherInfo(cipher_algorithm);
	const index_key = crypto.scryptSync(password, salt, keyLength);
	const index_iv = crypto.randomBytes(ivLength);
	const cipher = crypto.createCipheriv(cipher_algorithm, index_key, index_iv);
	const files = Buffer.concat([cipher.update(v8.serialize(index)), cipher.final()]);
	return v8.serialize({ cipher_algorithm, hash_algorithm, split_size, salt, index_iv, files });
}

function init({ crypt: crypt_dir, cipher: cipher_algorithm = DEFAULT_CIPHER_ALGORITHM, hash: hash_algorithm = DEFAULT_HASH_ALGORITHM, split: split_size, password }) {
	fs.mkdirSync(crypt_dir, { recursive: true });
	fs.writeFileSync(crypt_dir + '/-', make_info({ cipher_algorithm, hash_algorithm, split_size, password, index: new Map() }), { flag: 'wx' });
}

function get_info({ crypt_dir, password }) {
	const { cipher_algorithm, hash_algorithm, split_size, salt, index_iv, files } = v8.deserialize(fs.readFileSync(crypt_dir + '/-'));
	const { keyLength } = crypto.getCipherInfo(cipher_algorithm);
	const index_key = crypto.scryptSync(password, salt, keyLength);
	const decipher = crypto.createDecipheriv(cipher_algorithm, index_key, index_iv);
	const index = v8.deserialize(Buffer.concat([decipher.update(files), decipher.final()]));
	return { cipher_algorithm, hash_algorithm, split_size, index, password };
}

async function get_plain_index({ plain_dir, hash_algorithm, filter }) {
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

async function encrypt({ plain: plain_dir, crypt: crypt_dir, filter, password }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	// READ CRYPT INDEX
	const info = get_info({ crypt_dir, password });
	const { keyLength, ivLength } = crypto.getCipherInfo(info.cipher_algorithm);
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index({ plain_dir, hash_algorithm: info.hash_algorithm, filter });
	// DELETE MISSING FILES
	for (const [path, { files }] of info.index) {
		if (!plain_index.has(path)) {
			deleted.add(path);
			info.index.delete(path);
			for (const file of files) {
				fs.unlinkSync(crypt_dir + '/' + file);
			}
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path, { size, hash }] of plain_index) {
		if (!info.index.has(path)) {
			added.add(path);
		} else if (Buffer.compare(info.index.get(path).hash, hash)) {
			updated.add(path);
		} else {
			continue;
		}
		const key = crypto.randomBytes(keyLength);
		const iv = crypto.randomBytes(ivLength);
		if (info.index.has(path)) {
			for (const file of info.index.get(path).files) {
				fs.unlinkSync(crypt_dir + '/' + file);
			}
		}
		const files = [];
		for (let start = 0; start < size; start += info.split_size) {
			const crypt_filename = crypto.randomUUID();
			files.push(crypt_filename);
			const cipher = crypto.createCipheriv(info.cipher_algorithm, key, iv);
			stream_queue.enqueue(() =>
				fs
					.createReadStream(plain_dir + '/' + path, { start, end: Math.min(start + info.split_size - 1, size - 1) })
					.pipe(cipher)
					.pipe(fs.createWriteStream(crypt_dir + '/' + crypt_filename)),
			);
		}
		info.index.set(path, { hash, key, iv, files });
	}
	if (added.size > 0 || updated.size > 0) {
		await stream_queue.promise;
	}
	// WRITE INDEX
	if (added.size > 0 || deleted.size > 0 || updated.size > 0) {
		fs.writeFileSync(crypt_dir + '/-', make_info(info));
	}
	return { added, deleted, updated };
}

async function decrypt({ plain: plain_dir, crypt: crypt_dir, filter, password }) {
	const added = new Set();
	const deleted = new Set();
	const updated = new Set();
	fs.mkdirSync(plain_dir, { recursive: true });
	// READ CRYPT INDEX
	const info = get_info({ crypt_dir, password });
	// CONSTRUCT PLAIN INDEX
	const plain_index = await get_plain_index({ plain_dir, hash_algorithm: info.hash_algorithm, filter });
	// DELETE MISSING FILES
	for (const [path] of plain_index) {
		if (!info.index.has(path)) {
			deleted.add(path);
			fs.unlinkSync(plain_dir + '/' + path);
		}
	}
	// UPDATE/ADD FILES
	const stream_queue = make_stream_queue();
	for (const [path, { hash, key, iv, files }] of info.index) {
		if (!plain_index.has(path)) {
			added.add(path);
		} else if (Buffer.compare(plain_index.get(path).hash, hash)) {
			updated.add(path);
		} else {
			continue;
		}
		fs.mkdirSync(plain_dir + '/' + path_.dirname(path), { recursive: true });
		fs.writeFileSync(plain_dir + '/' + path, Buffer.alloc(0));
		for (let i = 0; i < files.length; i++) {
			const decipher = crypto.createDecipheriv(info.cipher_algorithm, key, iv);
			stream_queue.enqueue(() =>
				fs
					.createReadStream(crypt_dir + '/' + files[i])
					.pipe(decipher)
					.pipe(fs.createWriteStream(plain_dir + '/' + path, { start: i * info.split_size, flags: 'r+' })),
			);
		}
	}
	if (added.size > 0 || updated.size > 0) {
		await stream_queue.promise;
	}
	return { added, deleted, updated };
}

module.exports = { init, encrypt, decrypt };
