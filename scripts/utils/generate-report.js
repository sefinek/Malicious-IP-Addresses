const fs = require('node:fs');
const ipaddr = require('ipaddr.js');

class LogParser {
	constructor() {
		this.filePath = 'ddos.txt';
		this.categoryType = 'abuseipdb';
		this.ipDataMap = new Map();
		this.uniqueIPv4 = new Set();
		this.uniqueIPv6 = new Set();
		this.stats = {
			totalLines: 0,
			parsedLines: 0,
			invalidLines: 0,
		};
		this.logPatterns = [
			/^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}\.\d{2}\.\d{4}):\s+\[.*?]\s+(\S+)\s+-\s+(.*?)\s+-\s+([\da-fA-F:.]+)\s+"([^"]*)".*$/,
			/^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d{2}\.\d{2}\.\d{4}):\s+\[.*?]\s+(\S+)\s+-\s+(\S+)\s+-\s+([\da-fA-F:.]+)\s+"([^"]*)".*$/,
		];
	}

	isValidIP(ip) {
		if (!ip) return false;

		try {
			const cleanIP = ip.trim();
			const addr = ipaddr.process(cleanIP);

			if (addr.kind() === 'ipv4') {
				this.uniqueIPv4.add(cleanIP);
			} else if (addr.kind() === 'ipv6') {
				this.uniqueIPv6.add(cleanIP);
			} else {
				return false;
			}

			return true;
		} catch {
			return false;
		}
	}

	getCategory() {
		return this.categoryType === 'abuseipdb' ? '18' : '3';
	}

	generateComment(entry) {
		let comment = `DDoS Attack: HTTP requests trying to impersonate browsers. Endpoint ${entry.endpoint}`;

		if (entry.userAgent && entry.userAgent !== '-') {
			comment += `. UA: ${entry.userAgent}`;
		}

		return comment;
	}

	calculateScore(entry) {
		const uaLength = (entry.userAgent && entry.userAgent !== '-') ? entry.userAgent.length : 0;
		const refLength = (entry.referer && entry.referer !== '-') ? entry.referer.length : 0;
		return uaLength + refLength;
	}

	parseLogLine(line) {
		const cleanLine = line.replace(/\r/g, '').trim();
		if (!cleanLine) return null;

		for (const pattern of this.logPatterns) {
			const match = cleanLine.match(pattern);
			if (match) {
				const [, time, date, endpoint, userAgent, ip, referer] = match;

				if (!this.isValidIP(ip)) continue;

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
		}

		return null;
	}

	parseLogFile() {
		console.log(`Starting to parse file: ${this.filePath}`);

		if (!fs.existsSync(this.filePath)) {
			throw new Error(`File not found: ${this.filePath}`);
		}

		const stats = fs.statSync(this.filePath);
		const content = fs.readFileSync(this.filePath, 'utf8');
		const lines = content.split(/\r?\n/);

		this.stats.totalLines = lines.length;
		console.log(`${(stats.size / 1024 / 1024).toFixed(2)} MB of size, ${lines.length} lines`);

		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (!line.trim()) continue;

			const parsed = this.parseLogLine(line);
			if (parsed) {
				const existing = this.ipDataMap.get(parsed.ip);

				if (!existing || this.calculateScore(parsed) > this.calculateScore(existing)) {
					this.ipDataMap.set(parsed.ip, parsed);
				}

				this.stats.parsedLines++;
			} else {
				this.stats.invalidLines++;
			}

			if ((i + 1) % 10000 === 0) {
				console.log(`Processed ${i + 1}/${lines.length} lines...`);
			}
		}

		console.log(`Parsing completed! Valid: ${this.stats.parsedLines}, invalid: ${this.stats.invalidLines}`);
	}

	generateReports() {
		console.log('Generating reports...');

		if (this.ipDataMap.size === 0) {
			throw new Error('No valid entries found');
		}

		const csvLines = [];
		const ipList = [];
		const category = this.getCategory();
		const dateStr = new Date().toISOString().split('T')[0];

		for (const [ip, entry] of this.ipDataMap) {
			const comment = this.generateComment(entry);
			csvLines.push(`"${ip}","${category}","${entry.date}","${comment}"`);
			ipList.push(ip);
		}

		const csvContent = '"IP","Categories","ReportDate","Comment"\n' + csvLines.join('\n');
		fs.writeFileSync(`${dateStr}.csv`, csvContent, 'utf8');
		console.log(`Generated log_report_${dateStr}.csv with ${csvLines.length} entries`);

		fs.writeFileSync(`${dateStr}.txt`, ipList.join('\n'), 'utf8');
		console.log(`Generated ip_addresses_${dateStr}.txt with ${ipList.length} unique IPs`);

		this.printStats();
	}

	printStats() {
		console.log(`Parsed & total lines: ${this.stats.parsedLines}/${this.stats.totalLines}`);
		console.log(`Invalid lines: ${this.stats.invalidLines}`);
		console.log(`IPv4 addresses: ${this.uniqueIPv4.size}`);
		console.log(`IPv6 addresses: ${this.uniqueIPv6.size}`);
		console.log(`All Unique IPs: ${this.ipDataMap.size}`);
	}
}

function main() {
	try {
		const parser = new LogParser();
		parser.parseLogFile();
		parser.generateReports();
	} catch (error) {
		console.error(`[FATAL] ${error.message}`);
		process.exit(1);
	}
}

main();