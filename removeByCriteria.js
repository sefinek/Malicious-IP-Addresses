import fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path, { dirname } from 'node:path';
import { parse } from 'csv-parse/sync';
import { stringify } from 'csv-stringify/sync';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const LISTS_DIR = path.join(__dirname, 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};

/**
 * CSV column mapping for criteria types.
 * Maps user-friendly names to CSV column names.
 */
const CRITERIA_COLUMNS = {
	endpoint: 'Endpoint',
	ip: 'IP',
	userAgent: 'User-Agent',
};

/**
 * Removes matching IPs from the main.txt file.
 * @param {string} filePath - Path to the text file
 * @param {Set<string>} ipsToRemove - Set of IPs to remove
 * @returns {Promise<number>} Number of lines removed
 */
const removeFromTxt = async (filePath, ipsToRemove) => {
	if (!existsSync(filePath)) return 0;

	try {
		const content = await fs.readFile(filePath, 'utf8');
		const originalLines = content.split('\n').map(line => line.trim()).filter(Boolean);
		const filteredLines = originalLines.filter(line => !ipsToRemove.has(line));

		await fs.writeFile(filePath, filteredLines.join('\n') + '\n', 'utf8');
		return originalLines.length - filteredLines.length;
	} catch (error) {
		console.error(`Error removing from TXT: ${error.message}`);
		return 0;
	}
};

/**
 * Removes matching rows from the CSV file based on criteria.
 * @param {string} filePath - Path to the CSV file
 * @param {string} criteria - Value to match
 * @param {string} columnName - Column name to search in
 * @returns {Promise<Object>} Object with removed count and IPs
 */
const removeFromCsv = async (filePath, criteria, columnName) => {
	if (!existsSync(filePath)) throw new Error(`CSV file not found: ${filePath}`);

	const content = await fs.readFile(filePath, 'utf8');
	const records = parse(content, { columns: true, skip_empty_lines: true });

	const matchingRecords = [];
	const remainingRecords = [];

	for (const record of records) {
		const cellValue = record[columnName];
		if (cellValue && cellValue.includes(criteria)) {
			matchingRecords.push(record);
		} else {
			remainingRecords.push(record);
		}
	}

	// Extract unique IPs from matching records
	const ipsToRemove = new Set(
		matchingRecords.map(r => r.IP).filter(Boolean)
	);

	// Write remaining records back to CSV
	if (remainingRecords.length > 0) {
		const csvContent = stringify(remainingRecords, { header: true, columns: Object.keys(remainingRecords[0]) });
		await fs.writeFile(filePath, csvContent, 'utf8');
	} else {
		// If no records left, create empty file with header
		const header = Object.keys(records[0] || {}).join(',') + '\n';
		await fs.writeFile(filePath, header, 'utf8');
	}

	return {
		removedCount: matchingRecords.length,
		ipsToRemove,
	};
};

/**
 * Main function to remove entries by criteria.
 * @param {string} criteria - Value to search for
 * @param {string} criteriaType - Type of criteria (endpoint, ip, userAgent)
 */
// eslint-disable-next-line no-unused-vars
const removeByCriteria = async (criteria, criteriaType) => {
	// Validation
	if (!criteria || !criteriaType) throw new Error('Both criteria and criteriaType are required parameters');

	if (!CRITERIA_COLUMNS[criteriaType]) {
		throw new Error(`Invalid criteriaType: ${criteriaType}. ` + `Valid options: ${Object.keys(CRITERIA_COLUMNS).join(', ')}`);
	}

	console.log(`Removing entries where ${criteriaType} contains: "${criteria}"`);

	try {
		// Remove from CSV and get IPs to remove
		const { removedCount, ipsToRemove } = await removeFromCsv(
			FILES.csv,
			criteria,
			CRITERIA_COLUMNS[criteriaType]
		);

		// Remove corresponding IPs from TXT
		let txtRemovedCount = 0;
		if (ipsToRemove.size > 0) {
			txtRemovedCount = await removeFromTxt(FILES.txt, ipsToRemove);
		}

		// Log results
		console.log('──────────────────────────────────────');
		console.log('Removal Summary:');
		console.log(`  CSV rows removed     : ${removedCount}`);
		console.log(`  TXT lines removed    : ${txtRemovedCount}`);
		console.log(`  Unique IPs affected  : ${ipsToRemove.size}`);
		console.log('──────────────────────────────────────');

		if (removedCount === 0) {
			console.warn(`No matching entries found for ${criteriaType}: "${criteria}"`);
		}

		return {
			csvRemoved: removedCount,
			txtRemoved: txtRemovedCount,
			ipsAffected: ipsToRemove.size,
		};
	} catch (error) {
		throw new Error(`Failed to remove by criteria: ${error.message}`);
	}
};

/**
 * Main execution function.
 */
(async () => {
	try {
		// Example usage - modify these values as needed
		// Only ONE of these should be uncommented at a time

		// Remove by user-agent
		// await removeByCriteria('Mozilla/5.0', 'userAgent');

		// Remove by IP
		// await removeByCriteria('192.168.1.1', 'ip');

		// Remove by endpoint
		// await removeByCriteria('/api/endpoint', 'endpoint');

		console.log('No criteria specified. Please edit the main() function to specify criteria.');
		console.log('Example usage:');
		console.log('  await removeByCriteria("value", "ip");');
		console.log('  await removeByCriteria("value", "endpoint");');
		console.log('  await removeByCriteria("value", "userAgent");');
	} catch (err) {
		console.error('[FATAL]', err.message);
		process.exit(1);
	}
})();