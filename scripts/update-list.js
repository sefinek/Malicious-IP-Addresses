const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const axios = require('./services/axios.js');

const TXT_FILE_PATH = path.join(__dirname, '..', 'lists', 'main.txt');
const CSV_FILE_PATH = path.join(__dirname, '..', 'lists', 'details.csv');

const loadUniqueIPsFromFile = async filePath => {
	const content = fs.existsSync(filePath) ? await fs.promises.readFile(filePath, 'utf8') : '';
	const lines = content.split('\n').map(line => line.trim()).filter(line => line !== '');
	return new Set(lines);
};

const loadCsvRayIds = async filePath => {
	const content = fs.existsSync(filePath) ? await fs.promises.readFile(filePath, 'utf8') : '';
	const records = parse(content, { columns: true, skip_empty_lines: true });
	return new Set(records.map(record => record.RayID.trim()));
};

const appendToFile = async (filePath, content) => {
	if (fs.existsSync(filePath)) {
		await fs.promises.appendFile(filePath, `\n${content}`);
	} else {
		await fs.promises.writeFile(filePath, content);
	}
};

(async () => {
	const apiKey = process.env.MALICIOUS_IPS_LIST_SECRET;
	if (!apiKey) throw new Error('MALICIOUS_IPS_LIST_SECRET environment variable not set');

	try {
		const res = await axios.get('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', {
			headers: { 'X-API-Key': apiKey },
		});

		const data = res.data?.logs || [];
		let newCsvEntries = 0, newIPsAdded = 0, skippedEntries = 0, totalLogsProcessed = 0;

		const existingIPs = await loadUniqueIPsFromFile(TXT_FILE_PATH);
		const existingRayIds = await loadCsvRayIds(CSV_FILE_PATH);

		if (data.length > 0) {
			if (!fs.existsSync(CSV_FILE_PATH)) await fs.promises.writeFile(CSV_FILE_PATH, 'Added,Date,RayID,IP,Endpoint,User-Agent,"Action taken",Country\n');

			for (const entry of data) {
				const { rayId, ip, endpoint, userAgent, action, country, timestamp } = entry;
				totalLogsProcessed++;

				if (!existingIPs.has(ip)) {
					await appendToFile(TXT_FILE_PATH, ip);
					existingIPs.add(ip);
					newIPsAdded++;
				}

				if (!existingRayIds.has(rayId)) {
					const logEntry = [
						new Date().toISOString(),
						new Date(timestamp).toISOString(),
						rayId,
						ip,
						`${(/[";,]/g).test(endpoint) ? `"${endpoint.replace(/"/g, '\'')}"` : endpoint}`,
						`${(/[";, ]/g).test(userAgent) ? `"${userAgent.replace(/"/g, '\'')}"` : userAgent}`,
						action,
						country,
					].join(',');

					await fs.promises.appendFile(CSV_FILE_PATH, `\n${logEntry}`);
					existingRayIds.add(rayId);
					newCsvEntries++;
				} else {
					skippedEntries++;
				}
			}
		}

		console.log(`Total logs processed: ${totalLogsProcessed}`);
		console.log(`New IPs added to list: ${newIPsAdded}`);
		console.log(`New entries added to CSV: ${newCsvEntries}`);
		console.log(`Skipped entries: ${skippedEntries}`);
	} catch (err) {
		console.error(err.stack);
		process.exit(1);
	}
})();