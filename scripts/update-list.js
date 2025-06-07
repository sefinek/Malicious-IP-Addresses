const fs = require('node:fs/promises');
const { existsSync } = require('node:fs');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const axios = require('./services/axios.js');

(async () => {
	const apiKey = process.argv.find(arg => arg.startsWith('--secret='))?.split('=')[1];
	if (!apiKey) throw new Error('--secret not provided');

	const listsDir = path.join(__dirname, '..', 'lists');
	const txtPath = path.join(listsDir, 'main.txt');
	const csvPath = path.join(listsDir, 'details.csv');

	await fs.mkdir(listsDir, { recursive: true });

	const ipSet = new Set();
	if (existsSync(txtPath)) {
		const content = await fs.readFile(txtPath, 'utf8');
		content.split(/\r?\n/).forEach(line => line.trim() && ipSet.add(line.trim()));
	}

	const raySet = new Set();
	if (existsSync(csvPath)) {
		const content = await fs.readFile(csvPath, 'utf8');
		parse(content, { columns: true, skip_empty_lines: true })
			.map(r => r.RayID?.trim())
			.filter(Boolean)
			.forEach(id => raySet.add(id));
	}

	const newIps = [], newRows = [];
	let skipped = 0;

	const res = await axios.get('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', { headers: { 'X-API-Key': apiKey } });
	const logs = res.data?.logs ?? [];
	for (const log of logs) {
		const { rayId, ip, endpoint, userAgent, action, country, timestamp } = log;
		if (!ipSet.has(ip)) {
			ipSet.add(ip);
			newIps.push(ip);
		}

		if (!raySet.has(rayId)) {
			raySet.add(rayId);
			newRows.push({
				Added: new Date().toISOString(),
				Date: new Date(timestamp).toISOString(),
				RayID: rayId,
				IP: ip,
				Endpoint: endpoint,
				'User-Agent': userAgent,
				'Action taken': action,
				Country: country,
			});
		} else {
			skipped++;
		}
	}

	if (newIps.length) {
		let prefix = '';
		if (existsSync(txtPath)) {
			const tail = await fs.readFile(txtPath, 'utf8');
			if (!(/\r?\n$/).test(tail)) prefix = '\n';
		}
		await fs.appendFile(txtPath, prefix + newIps.join('\n') + '\n', 'utf8');
	}

	if (newRows.length) {
		const header = !existsSync(csvPath);
		await fs.appendFile(
			csvPath,
			stringify(newRows, { header }),
			'utf8'
		);
	}

	console.log(`Total logs processed:     ${logs.length}`);
	console.log(`New IPs added to list:    ${newIps.length}`);
	console.log(`New entries added to CSV: ${newRows.length}`);
	console.log(`Skipped entries:          ${skipped}`);
})();