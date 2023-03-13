#!/bin/env node
import { accessSync } from 'node:fs';
import { resolve } from 'node:path';
import { encrypt, decrypt, clean } from './crypt.js';
import { get_pass } from './pass.js';

const find_store = () => {
	do {
		try {
			accessSync('info');
			accessSync('public');
			accessSync('private');
			return;
		} catch {}
	} while (process.cwd() !== (process.chdir('..'), process.cwd()));
	console.log('Encrypted file store could not be found');
	process.exit(1);
};

const get_config = async () => {
	for (const ext of ['js', 'mjs', 'cjs']) {
		try {
			return await import(process.cwd() + '/split-crypt.config.' + ext);
		} catch {}
	}
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

if (process.argv[2] === 'e' || process.argv[2] === 'r') {
	find_store();
	const config = await get_config();
	if (typeof config?.plain !== 'string') {
		console.log('`plain` must be specified in split-crypt.config.[c|m]js');
		process.exit(1);
	}
	display_results(
		await encrypt({
			crypt: process.cwd(),
			plain: config.plain,
			cache: config.cache,
			filter: config.filter,
			passphrase: process.argv[2] === 'r' ? await get_pass('Enter passphrase: ') : null,
		}),
	);
} else if (process.argv[2] === 'd' && process.argv[3]) {
	const plain = resolve(process.argv[3]);
	find_store();
	const config = await get_config();
	display_results(
		await decrypt({
			crypt: process.cwd(),
			plain,
			cache: config?.cache,
			filter: config?.filter,
			passphrase: await get_pass('Enter passphrase: '),
		}),
	);
} else if (process.argv[2] === 'c') {
	find_store();
	display_results(
		await clean({
			crypt: process.cwd(),
			passphrase: await get_pass('Enter passphrase: '),
		}),
	);
} else {
	console.log(`Usage:
  split-crypt.js e
    Encrypt (does not require passphrase)
  split-crypt.js r
    Encrypt, delete unused -data files, support renamed files
  split-crypt.js d <target>
    Decrypt to target directory
  split-crypt.js c
    Clean unused -data files
`);
	process.exit(1);
}
