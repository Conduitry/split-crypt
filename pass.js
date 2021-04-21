import { createInterface } from 'readline';
import { Writable } from 'stream';

const devnull = new Writable({ write: (chunk, encoding, cb) => cb() });

export function get_pass(prompt) {
	process.stdout.write(prompt);
	return new Promise((res, rej) => {
		const rl = createInterface({ input: process.stdin, output: devnull, terminal: true })
			.once('line', (line) => {
				res(line);
				rl.close();
			})
			.once('close', () => {
				process.stdout.write('\n');
				rej();
			});
	});
}

export async function confirm_pass(prompt1, prompt2, error) {
	for (;;) {
		const pass1 = await get_pass(prompt1);
		const pass2 = await get_pass(prompt2);
		if (pass1 === pass2) {
			return pass1;
		}
		process.stdout.write(error + '\n');
	}
}
