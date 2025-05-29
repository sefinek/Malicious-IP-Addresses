const cluster = require('node:cluster');
const numCPUs = require('node:os').availableParallelism();
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

const WHITELISTS = ['https://raw.githubusercontent.com/sefinek/GoodBots-IP-Whitelist/main/lists/all-safe-ips.txt'];

// Master-only
let exitCount = 0;
let done = 0;
const removedTxtAll = [];
const removedCsvAll = [];

const fetchAllWhitelists = async () => {
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
	console.log(`[Master 0] fetchAllWhitelists: fetched ${unique.length} unique entries`);
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
	console.log(`[Master 0] readLines: reading ${file}`);

	try {
		const txt = await fs.readFile(file, 'utf8');
		const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
		console.log(`[Master 0] readLines: got ${lines.length} lines`);
		return lines;
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const readCsv = async file => {
	console.log(`[Master 0] readCsv: reading ${file}`);

	try {
		const txt = await fs.readFile(file, 'utf8');
		const rows = parse(txt, { columns: true, skip_empty_lines: true });
		console.log(`[Master 0] readCsv: got ${rows.length} rows`);
		return rows;
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const writeLines = (file, lines) =>
	fs.writeFile(file, lines.join('\n'), 'utf8')
		.then(() => console.log(`[Master 0] writeLines: wrote ${lines.length} lines to ${file}`));

const writeCsv = (file, rows) => {
	const out = rows.length ? stringify(rows, { header: true }) : '';
	return fs.writeFile(file, out, 'utf8')
		.then(() => console.log(`[Master 0] writeCsv: wrote ${rows.length} rows to ${file}`));
};

const chunk = arr => {
	const out = Array.from({ length: numCPUs }, () => []);
	arr.forEach((x, i) => out[i % numCPUs].push(x));
	return out;
};

(async () => {
	if (cluster.isPrimary) {
		console.log('[Master 0] start');
		await fs.mkdir(LISTS_DIR, { recursive: true });

		const whitelist = await fetchAllWhitelists();
		if (!whitelist.length) {
			console.log('[Master 0] no whitelist entries, exiting...');
			return;
		}

		const allTxt = await readLines(FILES.txt);
		const allCsv = await readCsv(FILES.csv);

		console.log(`[Master 0] CPU cores: ${numCPUs}, spawning workers`);

		const txtChunks = chunk(allTxt);
		const csvChunks = chunk(allCsv);

		for (let i = 0; i < numCPUs; i++) {
			const w = cluster.fork();
			console.log(`[Master 0] forked worker ${w.id}`);

			w.send({ wl: whitelist, txt: txtChunks[i], csv: csvChunks[i] });
			w.on('message', msg => {
				console.log(`[Master 0] from worker ${w.id}: removed ${msg.removedTxt.length} txt, ${msg.removedCsv.length} csv`);
				removedTxtAll.push(...msg.removedTxt);
				removedCsvAll.push(...msg.removedCsv);
				done++;

				if (done === numCPUs) {
					console.log('[Master 0] all workers done, aggregating removals');
					const remTxtSet = new Set(removedTxtAll);
					const remCsvSet = new Set(removedCsvAll);

					const filteredTxt = allTxt.filter(ip => !remTxtSet.has(ip));
					const filteredCsv = allCsv.filter(r => {
						const ip = r.IP?.trim();
						return !remCsvSet.has(ip);
					});

					writeLines(FILES.txt, filteredTxt);
					writeCsv(FILES.csv, filteredCsv);
					console.log(`[Master 0] main.txt: removed ${allTxt.length - filteredTxt.length}`);
					console.log(`[Master 0] details.csv: removed ${allCsv.length - filteredCsv.length}`);
					console.log('[Master 0] processing complete ✅');
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

			console.log(`[Worker ${cluster.worker.id}] done: txt->${removedTxt.length}, csv->${removedCsv.length}`);
			process.send({ removedTxt, removedCsv });
			process.exit();
		});
	}

	cluster.on('exit', (worker, code) => {
		console.log(`[Master 0] worker ${worker.id} exited (code=${code})`);
		if (cluster.isMaster) {
			exitCount++;
			if (exitCount === numCPUs) console.log('[Master 0] all workers exited');
		}
	});
})();