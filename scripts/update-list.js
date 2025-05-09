const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const axios = require('./services/axios.js');

const TXT_FILE_PATH = path.join(__dirname, '..', 'lists', 'main.txt');
const CSV_FILE_PATH = path.join(__dirname, '..', 'lists', 'details.csv');

const readLinesAsSet = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		return new Set(content.split('\n').map(l => l.trim()).filter(Boolean));
	} catch (err) {
		if (err.code === 'ENOENT') return new Set();
		throw err;
	}
};

const readCsvRayIds = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		const records = parse(content, { columns: true, skip_empty_lines: true });
		return new Set(records.map(r => r.RayID.trim()));
	} catch (err) {
		if (err.code === 'ENOENT') return new Set();
		throw err;
	}
};

const appendLineToFile = async (filePath, line) => {
	await fs.appendFile(filePath, `${line}\n`, 'utf8');
};

const appendCsvRows = async (filePath, rows) => {
	const csv = stringify(rows, { header: !fsSync.existsSync(filePath) });
	await fs.appendFile(filePath, csv, 'utf8');
};

(async () => {
	const apiKey = process.env.MALICIOUS_IPS_LIST_SECRET;
	if (!apiKey) throw new Error('MALICIOUS_IPS_LIST_SECRET environment variable not set');

	try {
		const { data: { logs = [] } = {} } = await axios.get(
			'https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb',
			{ headers: { 'X-API-Key': apiKey } }
		);

		const existingIPs = await readLinesAsSet(TXT_FILE_PATH);
		const existingRayIds = await readCsvRayIds(CSV_FILE_PATH);
		const newCsvRows = [];

		let newCsv = 0, newIPs = 0, skipped = 0, total = 0;

		for (const log of logs) {
			const { rayId, ip, endpoint, userAgent, action, country, timestamp } = log;
			total++;

			if (!existingIPs.has(ip)) {
				await appendLineToFile(TXT_FILE_PATH, ip);
				existingIPs.add(ip);
				newIPs++;
			}

			if (!existingRayIds.has(rayId)) {
				newCsvRows.push({
					Added: new Date().toISOString(),
					Date: new Date(timestamp).toISOString(),
					RayID: rayId,
					IP: ip,
					Endpoint: endpoint,
					'User-Agent': userAgent,
					'Action taken': action,
					Country: country,
				});
				existingRayIds.add(rayId);
				newCsv++;
			} else {
				skipped++;
			}
		}

		if (newCsvRows.length > 0) {
			await appendCsvRows(CSV_FILE_PATH, newCsvRows);
		}

		console.log(`Total logs processed:     ${total}`);
		console.log(`New IPs added to list:    ${newIPs}`);
		console.log(`New entries added to CSV: ${newCsv}`);
		console.log(`Skipped entries:          ${skipped}`);
	} catch (err) {
		console.error('[ERROR]', err.stack || err);
		process.exit(1);
	}
})();