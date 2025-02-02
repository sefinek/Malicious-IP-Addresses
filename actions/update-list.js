const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const axios = require('../utils/services/axios.js');

const listFilePath = path.join(__dirname, '..', 'lists', 'main.txt');
const logsFilePath = path.join(__dirname, '..', 'lists', 'details.csv');

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
	try {
		const apiKey = process.env.MALICIOUS_IPS_LIST_SECRET;
		if (!apiKey) throw new Error('MALICIOUS_IPS_LIST_SECRET environment variable not set');

		const res = await axios.get('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', {
			headers: { 'Authorization': apiKey },
		});

		const data = res.data?.logs || [];
		let newCsvEntries = 0, newIPsAdded = 0, skippedEntries = 0, totalLogsProcessed = 0;

		const existingIPs = await loadUniqueIPsFromFile(listFilePath);
		const existingRayIds = await loadCsvRayIds(logsFilePath);

		if (data.length > 0) {
			if (!fs.existsSync(logsFilePath)) await fs.promises.writeFile(logsFilePath, 'Added,Date,RayID,IP,Endpoint,User-Agent,"Action taken",Country\n');

			for (const entry of data) {
				const { rayId, ip, endpoint, userAgent, action, country, timestamp } = entry;
				totalLogsProcessed++;

				if (!existingIPs.has(ip)) {
					await appendToFile(listFilePath, ip);
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

					await fs.promises.appendFile(logsFilePath, `\n${logEntry}`);
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
		console.error(err);
		process.exit(1);
	}
})();