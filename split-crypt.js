#!/bin/env node
import { resolve } from 'node:path';
import { encrypt, decrypt, clean } from './crypt.js';
import { get_pass } from './pass.js';

const get_config = async () => {
	do {
		for (const ext of ['js', 'mjs', 'cjs']) {
			const file = 'split-crypt.config.' + ext;
			try {
				return await import(process.cwd() + '/' + file);
			} catch {}
		}
	} while (process.cwd() !== (process.chdir('..'), process.cwd()));
	console.log('split-crypt.config.[c|m]js not found or could not be loaded');
	process.exit(1);
};

const display_results = (results) => {
	for (const operation in results) {
		const { size } = results[operation];
		console.log(`${operation} ${size} file${size === 0 ? 's.' : size === 1 ? ':' : 's:'}`);
		for (const file of results[operation]) {
			console.log(`  ${file}`);
		}
	}
};

if (process.argv[2] === 'e') {
	const config = await get_config();
	display_results(
		await encrypt({
			crypt: process.cwd(),
			plain: config.plain,
			cache: config.cache,
			filter: config.filter,
		}),
	);
} else if (process.argv[2] === 'd' && process.argv[3]) {
	const plain = resolve(process.argv[3]);
	const config = await get_config();
	display_results(
		await decrypt({
			crypt: process.cwd(),
			plain,
			cache: config.cache,
			filter: config.filter,
			passphrase: await get_pass('Enter passphrase: '),
		}),
	);
} else if (process.argv[2] === 'c') {
	await get_config();
	display_results(
		await clean({
			crypt: process.cwd(),
			passphrase: await get_pass('Enter passphrase: '),
		}),
	);
} else {
	console.log(`Usage:
  split-crypt.js e
    Encrypt
  split-crypt.js d <target>
    Decrypt
  split-crypt.js c
    Clean
`);
	process.exit(1);
}
