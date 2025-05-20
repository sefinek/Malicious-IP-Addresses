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

const fetchAllWhitelists = async () => {
	try {
		const results = await Promise.all(
			WHITELISTS.map(url => axios.get(url).then(r => {
				if (r.status !== 200) throw new Error(`Status Code: ${r.status}`);
				return r.data.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
			}))
		);
		const all = [...new Set(results.flat())];
		console.log(`Fetched ${all.length} unique whitelist entries`);
		return all;
	} catch (err) {
		console.error(err);
		return [];
	}
};

const isWhitelisted = (ip, set) => {
	try {
		const parsed = ipaddr.parse(ip);
		if (set.has(ip)) return true;
		for (const w of set) {
			if (w.includes('/')) {
				const [network, prefix] = ipaddr.parseCIDR(w);
				if (parsed.kind() === network.kind() && parsed.match([network, prefix])) return true;
			}
		}
	} catch {
		return false;
	}
	return false;
};

const readLines = async file => {
	try {
		const content = await fs.readFile(file, 'utf8');
		return content.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const readCsv = async file => {
	try {
		const content = await fs.readFile(file, 'utf8');
		return parse(content, { columns: true, skip_empty_lines: true });
	} catch (e) {
		if (e.code === 'ENOENT') return [];
		throw e;
	}
};

const writeLines = async (file, lines) => {
	await fs.writeFile(file, lines.join('\n'), 'utf8');
};

const writeCsv = async (file, rows) => {
	const output = rows.length ? stringify(rows, { header: true }) : '';
	await fs.writeFile(file, output, 'utf8');
};

(async () => {
	try {
		await fs.mkdir(LISTS_DIR, { recursive: true });
		console.log('Starting processing...');

		const whitelist = await fetchAllWhitelists();
		if (!whitelist.length) return console.log('No whitelisted IPs found, skipping processing.');

		const set = new Set(whitelist);
		const txtLines = await readLines(FILES.txt);
		const filteredTxt = txtLines.filter(ip => !isWhitelisted(ip, set));
		await writeLines(FILES.txt, filteredTxt);
		console.log(`main.txt: removed ${txtLines.length - filteredTxt.length}`);

		const csvRows = await readCsv(FILES.csv);
		const filteredCsv = csvRows.filter(r => r.IP && !isWhitelisted(r.IP.trim(), set));
		await writeCsv(FILES.csv, filteredCsv);
		console.log(`details.csv: removed ${csvRows.length - filteredCsv.length}`);
	} catch (err) {
		console.error(err);
		process.exit(1);
	}
})();