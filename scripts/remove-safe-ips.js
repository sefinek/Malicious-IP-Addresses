const cluster = require('node:cluster');
const { cpus } = require('node:os');
const fs = require('node:fs/promises');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const ipaddr = require('ipaddr.js');
const axios = require('./services/axios.js');

const LISTS_DIR = path.join(__dirname, '..', 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};
const WHITELISTS = ['https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips'];

// Master-only
let exitCount = 0;
let done = 0;
const removedTxtAll = [];
const removedCsvAll = [];

const fetchAllWhitelists = async () => {
	console.log('[Master] fetchAllWhitelists: start');
	const results = await Promise.all(
		WHITELISTS.map(url =>
			axios.get(url).then(r => {
				if (r.status !== 200) throw new Error(`Status Code: ${r.status}`);
				return r.data
					.split(/\r?\n/)
					.map(l => l.trim())
					.filter(l => l && !l.startsWith('#'));
			})
		)
	);

	const unique = [...new Set(results.flat())];
	console.log(`[Master] fetchAllWhitelists: fetched ${unique.length} unique entries`);
	return unique;
};

const isWhitelisted = (ip, set) => {
	try {
		const p = ipaddr.parse(ip);
		if (set.has(ip)) return true;
		for (const w of set) {
			if (w.includes('/')) {
				const [net, pre] = ipaddr.parseCIDR(w);
				if (p.kind() === net.kind() && p.match([net, pre])) return true;
			}
		}
	} catch {}
	return false;
};

const readLines = async file => {
	console.log(`[Master] readLines: reading ${file}`);
	try {
		const txt = await fs.readFile(file, 'utf8');
		const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
		console.log(`[Master] readLines: got ${lines.length} lines`);
		return lines;
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const readCsv = async file => {
	console.log(`[Master] readCsv: reading ${file}`);
	try {
		const txt = await fs.readFile(file, 'utf8');
		const rows = parse(txt, { columns: true, skip_empty_lines: true });
		console.log(`[Master] readCsv: got ${rows.length} rows`);
		return rows;
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const writeLines = (file, lines) =>
	fs.writeFile(file, lines.join('\n'), 'utf8')
		.then(() => console.log(`[Master] writeLines: wrote ${lines.length} lines to ${file}`));

const writeCsv = (file, rows) => {
	const out = rows.length ? stringify(rows, { header: true }) : '';
	return fs.writeFile(file, out, 'utf8')
		.then(() => console.log(`[Master] writeCsv: wrote ${rows.length} rows to ${file}`));
};

const chunk = (arr, n) => {
	const out = Array.from({ length: n }, () => []);
	arr.forEach((x, i) => out[i % n].push(x));
	return out;
};

(async () => {
	if (cluster.isPrimary) {
		console.log('[Master] start');
		await fs.mkdir(LISTS_DIR, { recursive: true });

		const whitelist = await fetchAllWhitelists();
		if (!whitelist.length) {
			console.log('[Master] no whitelist entries, exiting...');
			return;
		}

		const allTxt = await readLines(FILES.txt);
		const allCsv = await readCsv(FILES.csv);

		const n = cpus().length;
		console.log(`[Master] CPU cores: ${n}, spawning workers`);
		const txtChunks = chunk(allTxt, n);
		const csvChunks = chunk(allCsv, n);

		for (let i = 0; i < n; i++) {
			const w = cluster.fork();
			console.log(`[Master] forked worker ${w.id}`);
			w.send({ wl: whitelist, txt: txtChunks[i], csv: csvChunks[i] });
			w.on('message', msg => {
				console.log(`[Master] from worker ${w.id}: removed ${msg.removedTxt.length} txt, ${msg.removedCsv.length} csv`);
				removedTxtAll.push(...msg.removedTxt);
				removedCsvAll.push(...msg.removedCsv);
				done++;
				if (done === n) {
					console.log('[Master] all workers done, aggregating removals');
					const remTxtSet = new Set(removedTxtAll);
					const remCsvSet = new Set(removedCsvAll);

					const filteredTxt = allTxt.filter(ip => !remTxtSet.has(ip));
					const filteredCsv = allCsv.filter(r => {
						const ip = r.IP?.trim();
						return !remCsvSet.has(ip);
					});

					writeLines(FILES.txt, filteredTxt);
					writeCsv(FILES.csv, filteredCsv);
					console.log(`[Master] main.txt: removed ${allTxt.length - filteredTxt.length}`);
					console.log(`[Master] details.csv: removed ${allCsv.length - filteredCsv.length}`);
					console.log('[Master] processing complete ✅');
				}
			});
		}
	} else {
		console.log(`[Worker ${cluster.worker.id}] start`);

		process.on('message', ({ wl, txt, csv }) => {
			console.log(`[Worker ${cluster.worker.id}] received ${txt.length} txt, ${csv.length} csv`);
			const set = new Set(wl);
			const removedTxt = txt.filter(ip => isWhitelisted(ip, set));
			const removedCsv = csv
				.filter(r => r.IP && isWhitelisted(r.IP.trim(), set))
				.map(r => r.IP.trim());
			console.log(
				`[Worker ${cluster.worker.id}] done: txt->${removedTxt.length}, csv->${removedCsv.length}`
			);
			process.send({ removedTxt, removedCsv });
			process.exit();
		});
	}

	cluster.on('exit', (worker, code) => {
		console.log(`[Master] worker ${worker.id} exited (code=${code})`);
		if (cluster.isMaster) {
			exitCount++;
			if (exitCount === cpus().length) console.log('[Master] all workers exited');
		}
	});
})();