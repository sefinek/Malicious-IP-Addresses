import fs from 'node:fs/promises';
import path, { dirname } from 'node:path';
import { parse } from 'csv-parse/sync';
import { stringify } from 'csv-stringify/sync';
import { fileURLToPath } from 'node:url';
import { classifyIp, compareIps } from './utils/ip-utils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const LISTS_DIR = path.join(__dirname, '..', 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};

/**
 * Formats a number as a percentage.
 * @param {number} value - The value to format
 * @param {number} total - The total for percentage calculation
 * @returns {string} Formatted percentage
 */
const formatPercent = (value, total) => {
	if (value === 0 || total === 0) return '0.000%';
	const percent = (value / total) * 100;
	return percent < 0.001 ? '<0.001%' : `${percent.toFixed(3)}%`;
};

/**
 * Logs statistics about the cleanup process.
 * @param {string} fileName - Name of the file being processed
 * @param {Object} counts - Statistics object
 * @param {boolean} duplicatesRemoved - Whether duplicates were removed
 */
const logStats = (fileName, counts, duplicatesRemoved = true) => {
	const total = counts.public + counts.nonPublic + counts.invalid + counts.duplicates;
	const removed = counts.nonPublic + counts.invalid + (duplicatesRemoved ? counts.duplicates : 0);

	console.log(`📄 ${fileName}`);
	console.log(`  • Total entries        : ${total}`);
	console.log(`  • Valid public         : ${counts.public}`);
	console.log(`  • Duplicate public IPs : ${counts.duplicates} (${formatPercent(counts.duplicates, total)})${duplicatesRemoved ? '' : ' [kept]'}`);
	console.log(`  • Removed non-public   : ${counts.nonPublic} (${formatPercent(counts.nonPublic, total)})`);
	console.log(`  • Removed invalid      : ${counts.invalid} (${formatPercent(counts.invalid, total)})`);
	console.log(`  • Total removed        : ${removed} (${formatPercent(removed, total)})`);
};

/**
 * Processes IP addresses and filters duplicates and invalid entries.
 * @param {Iterable<string>} ipAddresses - Iterator of IP addresses
 * @param {boolean} removeDuplicates - Whether to remove duplicate IPs
 * @returns {Object} Object containing cleaned IPs and statistics
 */
const processIpAddresses = (ipAddresses, removeDuplicates = true) => {
	const counts = { public: 0, nonPublic: 0, invalid: 0, duplicates: 0 };
	const seen = new Set();
	const cleaned = [];

	for (const ip of ipAddresses) {
		const type = classifyIp(ip);

		if (type === 'public') {
			if (removeDuplicates && seen.has(ip)) {
				counts.duplicates++;
			} else {
				if (removeDuplicates) seen.add(ip);
				if (!removeDuplicates && seen.has(ip)) {
					counts.duplicates++;
				} else {
					seen.add(ip);
				}
				cleaned.push(ip);
				counts.public++;
			}
		} else if (type === 'nonPublic') {
			counts.nonPublic++;
		} else {
			counts.invalid++;
		}
	}

	return { cleaned, counts };
};

/**
 * Cleans and processes a plain text file containing IP addresses.
 * @param {string} filePath - Path to the text file
 */
const cleanTextFile = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		const lines = content
			.split('\n')
			.map(line => line.trim())
			.filter(Boolean);

		const { cleaned, counts } = processIpAddresses(lines);

		cleaned.sort(compareIps);
		await fs.writeFile(filePath, cleaned.join('\n') + '\n', 'utf8');

		logStats(path.basename(filePath), counts);
	} catch (err) {
		if (err.code !== 'ENOENT') throw err;
	}
};

/**
 * Cleans and processes a CSV file containing IP addresses.
 * @param {string} filePath - Path to the CSV file
 */
const cleanCsvFile = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		const records = parse(content, { columns: true, skip_empty_lines: true });

		// Process records and filter invalid/non-public IPs
		const { counts } = processIpAddresses(
			records.map(row => row.IP || ''),
			false // Keep duplicates in CSV
		);

		const cleanedRecords = records.filter(row => {
			if (!row.IP) return false;
			const type = classifyIp(row.IP);
			return type === 'public';
		});

		// Sort by IP
		cleanedRecords.sort((a, b) => compareIps(a.IP, b.IP));

		// Update counts for missing IP column
		const missingIpCount = records.filter(row => !row.IP).length;
		counts.invalid += missingIpCount;

		if (cleanedRecords.length > 0) {
			const output = stringify(cleanedRecords, {
				header: true,
				columns: Object.keys(cleanedRecords[0]),
			});
			await fs.writeFile(filePath, output, 'utf8');
		} else {
			await fs.writeFile(filePath, '', 'utf8');
		}

		logStats(path.basename(filePath), counts, false);
	} catch (err) {
		if (err.code !== 'ENOENT') throw err;
	}
};

/**
 * Main execution function
 */
const main = async () => {
	await cleanTextFile(FILES.txt);
	console.log();
	await cleanCsvFile(FILES.csv);
};

main().catch(err => {
	console.error('Fatal error:', err);
	process.exit(1);
});
