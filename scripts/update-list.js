import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path, { dirname } from 'node:path';
import { parse } from 'csv-parse/sync';
import { stringify } from 'csv-stringify/sync';
import ipaddr from 'ipaddr.js';
import axios from './services/axios.js';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const LISTS_DIR = path.join(__dirname, '..', 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};

const NON_PUBLIC_RANGES = new Set([
	'unspecified', 'multicast', 'linkLocal', 'loopback', 'reserved', 'benchmarking',
	'amt', 'broadcast', 'carrierGradeNat', 'private', 'as112', 'uniqueLocal',
	'ipv4Mapped', 'rfc6145', '6to4', 'teredo', 'as112v6', 'orchid2', 'droneRemoteIdProtocolEntityTags',
]);

/**
 * Classifies an IP address as public, non-public, or invalid.
 * @param {string} ip - The IP address to classify
 * @returns {'public'|'nonPublic'|'invalid'} The classification
 */
const classifyIp = ip => {
	if (!ip || !ipaddr.isValid(ip)) return 'invalid';
	const range = ipaddr.parse(ip).range();
	return NON_PUBLIC_RANGES.has(range) ? 'nonPublic' : 'public';
};

/**
 * Compares two IP addresses for sorting.
 * @param {string} ipA - First IP address
 * @param {string} ipB - Second IP address
 * @returns {number} Comparison result
 */
const compareIps = (ipA, ipB) => {
	try {
		const parsedA = ipaddr.parse(ipA);
		const parsedB = ipaddr.parse(ipB);
		const bytesA = parsedA.toByteArray();
		const bytesB = parsedB.toByteArray();

		for (let i = 0; i < Math.max(bytesA.length, bytesB.length); i++) {
			const diff = (bytesA[i] || 0) - (bytesB[i] || 0);
			if (diff !== 0) return diff;
		}
		return 0;
	} catch {
		return ipA.localeCompare(ipB);
	}
};

/**
 * Loads existing IP addresses from the main.txt file.
 * @returns {Promise<Set<string>>} Set of existing IPs
 */
const loadExistingIps = async () => {
	const ipSet = new Set();
	if (existsSync(FILES.txt)) {
		const content = await fs.readFile(FILES.txt, 'utf8');
		content
			.split(/\r?\n/)
			.map(line => line.trim())
			.filter(Boolean)
			.forEach(ip => ipSet.add(ip));
	}
	return ipSet;
};

/**
 * Loads existing Ray IDs from the details.csv file.
 * @returns {Promise<Set<string>>} Set of existing Ray IDs
 */
const loadExistingRayIds = async () => {
	const raySet = new Set();
	if (existsSync(FILES.csv)) {
		const content = await fs.readFile(FILES.csv, 'utf8');
		const records = parse(content, { columns: true, skip_empty_lines: true });
		records
			.map(r => r.RayID?.trim())
			.filter(Boolean)
			.forEach(id => raySet.add(id));
	}
	return raySet;
};

/**
 * Fetches malicious IP logs from the API.
 * @param {string} apiKey - API key for authentication
 * @returns {Promise<Array>} Array of log entries
 */
const fetchLogs = async apiKey => {
	try {
		const response = await axios.get('https://api.sefinek.net/api/v2/cloudflare-waf-abuseipdb', {
			headers: { 'X-API-Key': apiKey },
			timeout: 30000,
		});

		if (!response.data?.logs) {
			throw new Error('Invalid API response: missing logs array');
		}

		return response.data.logs;
	} catch (error) {
		if (error.response) {
			throw new Error(`API error (${error.response.status}): ${error.response.statusText}`);
		} else if (error.request) {
			throw new Error('API error: No response received (network/timeout issue)');
		} else {
			throw new Error(`API error: ${error.message}`);
		}
	}
};

/**
 * Processes logs and extracts new valid entries.
 * @param {Array} logs - Log entries from API
 * @param {Set<string>} existingIps - Set of existing IPs
 * @param {Set<string>} existingRayIds - Set of existing Ray IDs
 * @returns {Object} Object containing new IPs, rows, and statistics
 */
const processLogs = (logs, existingIps, existingRayIds) => {
	const newIps = [];
	const newRows = [];
	const stats = {
		total: logs.length,
		skippedDuplicateRay: 0,
		skippedInvalidIp: 0,
		skippedNonPublicIp: 0,
		addedIps: 0,
		addedRows: 0,
	};

	const seenIps = new Set(existingIps);

	for (const log of logs) {
		const { rayId, ip, endpoint, userAgent, action, country, timestamp } = log;

		if (!rayId || !ip) {
			stats.skippedInvalidIp++;
			continue;
		}

		// Validate IP
		const ipType = classifyIp(ip);
		if (ipType === 'invalid') {
			stats.skippedInvalidIp++;
			continue;
		}
		if (ipType === 'nonPublic') {
			stats.skippedNonPublicIp++;
			continue;
		}

		// Add new IP to list (only once)
		if (!seenIps.has(ip)) {
			seenIps.add(ip);
			newIps.push(ip);
			stats.addedIps++;
		}

		// Add new CSV row (if RayID is unique)
		if (!existingRayIds.has(rayId)) {
			existingRayIds.add(rayId);
			newRows.push({
				Added: new Date().toISOString(),
				Date: new Date(timestamp).toISOString(),
				RayID: rayId,
				IP: ip,
				Endpoint: endpoint || '',
				'User-Agent': userAgent || '',
				'Action taken': action || '',
				Country: country || '',
			});
			stats.addedRows++;
		} else {
			stats.skippedDuplicateRay++;
		}
	}

	return { newIps, newRows, stats };
};

/**
 * Writes new IPs to the main.txt file.
 * @param {Array<string>} newIps - Array of new IPs to add
 */
const writeNewIps = async newIps => {
	if (newIps.length === 0) return;

	// Sort new IPs before adding
	newIps.sort(compareIps);

	// Check if file needs a newline prefix
	let prefix = '';
	if (existsSync(FILES.txt)) {
		const content = await fs.readFile(FILES.txt, 'utf8');
		if (!(/\r?\n$/).test(content)) {
			prefix = '\n';
		}
	}

	await fs.appendFile(FILES.txt, prefix + newIps.join('\n') + '\n', 'utf8');
};

/**
 * Writes new rows to the details.csv file.
 * @param {Array<Object>} newRows - Array of new rows to add
 */
const writeNewRows = async newRows => {
	if (newRows.length === 0) return;

	const header = !existsSync(FILES.csv);
	const csvContent = stringify(newRows, { header });

	await fs.appendFile(FILES.csv, csvContent, 'utf8');
};

/**
 * Logs processing statistics.
 * @param {Object} stats - Statistics object
 */
const logStats = stats => {
	console.log('──────────────────────────────────────');
	console.log('Processing Summary:');
	console.log(`  Total logs processed     : ${stats.total}`);
	console.log(`  New IPs added to list    : ${stats.addedIps}`);
	console.log(`  New entries added to CSV : ${stats.addedRows}`);
	console.log('──────────────────────────────────────');
	console.log('Skipped:');
	console.log(`  Duplicate Ray IDs        : ${stats.skippedDuplicateRay}`);
	console.log(`  Invalid IPs              : ${stats.skippedInvalidIp}`);
	console.log(`  Non-public IPs           : ${stats.skippedNonPublicIp}`);
	console.log('──────────────────────────────────────');
};

/**
 * Main execution function.
 */
const main = async () => {
	const apiKey = process.argv.find(arg => arg.startsWith('--secret='))?.split('=')[1];
	if (!apiKey) {
		throw new Error('API key not provided. Use: --secret=YOUR_API_KEY');
	}

	// Create lists directory if it doesn't exist
	await fs.mkdir(LISTS_DIR, { recursive: true });

	console.log('Loading existing data...');
	const [existingIps, existingRayIds] = await Promise.all([
		loadExistingIps(),
		loadExistingRayIds(),
	]);

	console.log(`Loaded ${existingIps.size} existing IPs and ${existingRayIds.size} Ray IDs`);

	console.log('Fetching logs from API...');
	const logs = await fetchLogs(apiKey);

	console.log('Processing logs...');
	const { newIps, newRows, stats } = processLogs(logs, existingIps, existingRayIds);

	console.log('Writing new data...');
	await Promise.all([
		writeNewIps(newIps),
		writeNewRows(newRows),
	]);

	logStats(stats);
};

main().catch(err => {
	console.error('Fatal error:', err.message);
	process.exit(1);
});
