const fs = require('node:fs/promises');
const fsSync = require('node:fs');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const axios = require('./services/axios.js');

const LISTS_DIR = path.join(__dirname, '..', 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};

const readLinesAsSet = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		return new Set(content.split(/\r?\n/).map(line => line.trim()).filter(Boolean));
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

(async () => {
	const apiKey = process.env.MALICIOUS_IPS_LIST_SECRET;
	if (!apiKey) throw new Error('MALICIOUS_IPS_LIST_SECRET environment variable not set');

	try {
		await fs.mkdir(LISTS_DIR, { recursive: true });

		const { data } = await axios.get('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', { headers: { 'X-API-Key': apiKey } });
		const logs = data?.logs ?? [];

		const existingIPs = await readLinesAsSet(FILES.txt);
		const existingRayIds = await readCsvRayIds(FILES.csv);

		const newIPsList = [];
		const newCsvRows = [];
		let newCsv = 0, newIPs = 0, skipped = 0, total = 0;

		for (const { rayId, ip, endpoint, userAgent, action, country, timestamp } of logs) {
			total++;

			if (!existingIPs.has(ip)) {
				newIPsList.push(ip);
				existingIPs.add(ip);
				newIPs++;
			}

			if (!existingRayIds.has(rayId)) {
				newCsvRows.push({
					Added:          new Date().toISOString(),
					Date:           new Date(timestamp).toISOString(),
					RayID:          rayId,
					IP:             ip,
					Endpoint:       endpoint,
					'User-Agent':   userAgent,
					'Action taken': action,
					Country:        country,
				});
				existingRayIds.add(rayId);
				newCsv++;
			} else {
				skipped++;
			}
		}

		if (newIPsList.length) {
			const txtPath = FILES.txt;
			let prefix = '';
			if (fsSync.existsSync(txtPath)) {
				const tail = await fs.readFile(txtPath, 'utf8');
				if (!tail.endsWith('\n')) prefix = '\n';
			}

			const block = prefix + newIPsList.join('\n') + '\n';
			await fs.appendFile(txtPath, block, 'utf8');
		}

		if (newCsvRows.length) {
			const csvPath = FILES.csv;
			const needHeader = !fsSync.existsSync(csvPath);
			const csvData = stringify(newCsvRows, { header: needHeader });
			await fs.appendFile(csvPath, csvData, 'utf8');
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