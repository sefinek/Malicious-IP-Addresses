import fs from 'node:fs';
import ipaddr from 'ipaddr.js';
import { compareIps } from './ip-utils.js';

const DEFAULT_CONFIG = {
	inputFile: 'ddos.txt',
	categoryType: 'abuseipdb', // 'abuseipdb' or other
	outputDateFormat: 'iso', // 'iso' for YYYY-MM-DD
};

const LOG_PATTERNS = [
	// Pattern 1: With referer
	/^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}\.\d{2}\.\d{4}):\s+\[.*?]\s+(\S+)\s+-\s+(.*?)\s+-\s+([\da-fA-F:.]+)\s+"([^"]*)".*$/,
	// Pattern 2: Without referer
	/^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}\.\d{2}\.\d{4}):\s+\[.*?]\s+(\S+)\s+-\s+(\S+)\s+-\s+([\da-fA-F:.]+)\s+"([^"]*)".*$/,
];

/**
 * Main class for parsing DDoS attack logs and generating reports.
 */
class LogParser {
	constructor(config = {}) {
		this.config = { ...DEFAULT_CONFIG, ...config };
		this.ipDataMap = new Map();
		this.uniqueIPv4 = new Set();
		this.uniqueIPv6 = new Set();
		this.stats = {
			totalLines: 0,
			parsedLines: 0,
			invalidLines: 0,
			fileSize: 0,
		};
	}

	/**
	 * Validates and classifies an IP address.
	 * @param {string} ip - IP address to validate
	 * @returns {boolean} True if IP is valid
	 */
	isValidIP(ip) {
		if (!ip) return false;

		try {
			const cleanIP = ip.trim();
			const addr = ipaddr.process(cleanIP);
			const kind = addr.kind();

			if (kind === 'ipv4') {
				this.uniqueIPv4.add(cleanIP);
				return true;
			} else if (kind === 'ipv6') {
				this.uniqueIPv6.add(cleanIP);
				return true;
			}

			return false;
		} catch {
			return false;
		}
	}

	/**
	 * Gets the category code based on category type.
	 * @returns {string} Category code
	 */
	getCategory() {
		return this.config.categoryType === 'abuseipdb' ? '18' : '3';
	}

	/**
	 * Generates a comment for the report entry.
	 * @param {Object} entry - Log entry object
	 * @returns {string} Generated comment
	 */
	generateComment(entry) {
		let comment = `DDoS Attack: Endpoint ${entry.endpoint}`;
		if (entry.userAgent && entry.userAgent !== '-') comment += `. UA: ${entry.userAgent}`;
		return comment;
	}

	/**
	 * Calculates a score for the entry (used to keep the best entry per IP).
	 * @param {Object} entry - Log entry object
	 * @returns {number} Score value
	 */
	calculateScore(entry) {
		const uaLength = (entry.userAgent && entry.userAgent !== '-') ? entry.userAgent.length : 0;
		const refLength = (entry.referer && entry.referer !== '-') ? entry.referer.length : 0;
		return uaLength + refLength;
	}

	/**
	 * Parses a single log line.
	 * @param {string} line - Log line to parse
	 * @returns {Object|null} Parsed entry or null if invalid
	 */
	parseLogLine(line) {
		const cleanLine = line.replace(/\r/g, '').trim();
		if (!cleanLine) return null;

		for (const pattern of LOG_PATTERNS) {
			const match = cleanLine.match(pattern);
			if (!match) continue;

			const [, time, date, endpoint, userAgent, ip, referer] = match;
			if (!this.isValidIP(ip)) continue;

			// Parse date: DD.MM.YYYY to ISO format
			const [day, month, year] = date.split('.');
			const isoDate = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}T${time}Z`;

			return {
				ip: ip.trim(),
				date: isoDate,
				endpoint: endpoint.trim(),
				userAgent: userAgent.trim(),
				referer: referer.trim(),
			};
		}

		return null;
	}

	/**
	 * Parses the entire log file.
	 */
	parseLogFile() {
		if (!fs.existsSync(this.config.inputFile)) throw new Error(`File not found: ${this.config.inputFile}`);

		console.log(`Starting to parse file: ${this.config.inputFile}`);

		const stats = fs.statSync(this.config.inputFile);
		this.stats.fileSize = stats.size;

		const content = fs.readFileSync(this.config.inputFile, 'utf8');
		const lines = content.split(/\r?\n/);

		this.stats.totalLines = lines.length;
		console.log(`File size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);
		console.log(`Total lines: ${lines.length}`);

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line.trim()) continue;

			const parsed = this.parseLogLine(line);
			if (parsed) {
				const existing = this.ipDataMap.get(parsed.ip);

				// Keep the entry with the highest score
				if (!existing || this.calculateScore(parsed) > this.calculateScore(existing)) this.ipDataMap.set(parsed.ip, parsed);

				this.stats.parsedLines++;
			} else {
				this.stats.invalidLines++;
			}

			// Progress indicator every 10k lines
			if ((i + 1) % 10000 === 0) {
				console.log(`Progress: ${i + 1}/${lines.length} lines...`);
			}
		}

		console.log('Parsing completed!');
		console.log(`  Valid lines: ${this.stats.parsedLines}`);
		console.log(`  Invalid lines: ${this.stats.invalidLines}`);
	}

	/**
	 * Generates CSV and TXT reports.
	 */
	generateReports() {
		console.log('Generating reports...');

		if (this.ipDataMap.size === 0) {
			throw new Error('No valid entries found to generate reports');
		}

		const csvLines = [];
		const ipList = [];
		const category = this.getCategory();
		const dateStr = new Date().toISOString().split('T')[0];

		// Sort IPs before processing
		const sortedEntries = Array.from(this.ipDataMap.entries()).sort((a, b) => compareIps(a[0], b[0]));
		for (const [ip, entry] of sortedEntries) {
			const comment = this.generateComment(entry);
			csvLines.push(`"${ip}","${category}","${entry.date}","${comment}"`);
			ipList.push(ip);
		}

		// Generate CSV file
		const csvFileName = `log_report_${dateStr}.csv`;
		const csvContent = '"IP","Categories","ReportDate","Comment"\n' + csvLines.join('\n') + '\n';
		fs.writeFileSync(csvFileName, csvContent, 'utf8');
		console.log(`Generated ${csvFileName} with ${csvLines.length} entries`);

		// Generate TXT file
		const txtFileName = `ip_addresses_${dateStr}.txt`;
		fs.writeFileSync(txtFileName, ipList.join('\n') + '\n', 'utf8');
		console.log(`Generated ${txtFileName} with ${ipList.length} unique IPs`);

		this.printStats();
	}

	/**
	 * Prints final statistics.
	 */
	printStats() {
		console.log('──────────────────────────────────────');
		console.log('Final Statistics:');
		console.log(`  Parsed lines         : ${this.stats.parsedLines}/${this.stats.totalLines}`);
		console.log(`  Invalid lines        : ${this.stats.invalidLines}`);
		console.log(`  Unique IPv4 addresses: ${this.uniqueIPv4.size}`);
		console.log(`  Unique IPv6 addresses: ${this.uniqueIPv6.size}`);
		console.log(`  Total unique IPs     : ${this.ipDataMap.size}`);
		console.log('──────────────────────────────────────');
	}
}

/**
 * Main execution function.
 */

(async () => {
	try {
		const parser = new LogParser();
		parser.parseLogFile();
		parser.generateReports();
		console.log('Report generation completed successfully!');
	} catch (err) {
		console.error('[FATAL]', err.message);
		process.exit(1);
	}
})();