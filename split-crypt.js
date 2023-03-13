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
	do {
		for (const ext of ['js', 'mjs', 'cjs']) {
			const file = 'split-crypt.config.' + ext;
			try {
				const config = await import(process.cwd() + '/' + file);
				if (
					typeof config.plain !== 'string' ||
					(config.filter && typeof config.filter !== 'function') ||
					(config.cache && typeof config.cache !== 'string')
				) {
					console.log(`Invalid configuration shape in ${process.cwd()}/${file}`);
					process.exit(1);
				}
				return config;
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
	find_store();
	const config = await get_config();
	display_results(
		await encrypt({
			crypt: process.cwd(),
			plain: config.plain,
			cache: config.cache,
			filter: config.filter,
		}),
	);
} else if (process.argv[2] === 'r') {
	find_store();
	const config = await get_config();
	display_results(
		await encrypt({
			crypt: process.cwd(),
			plain: config.plain,
			cache: config.cache,
			filter: config.filter,
			passphrase: await get_pass('Enter passphrase: '),
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
			cache: config.cache,
			filter: config.filter,
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
