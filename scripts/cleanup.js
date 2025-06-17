const fs = require('node:fs/promises');
const path = require('node:path');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const ipaddr = require('ipaddr.js');

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

const classifyIp = ip => {
	if (!ipaddr.isValid(ip)) return 'invalid';
	const range = ipaddr.parse(ip).range();
	return NON_PUBLIC_RANGES.has(range) ? 'nonPublic' : 'public';
};

const logStats = (fileName, counts) => {
	const total = counts.public + counts.nonPublic + counts.invalid;
	const removed = counts.nonPublic + counts.invalid;
	const percent = n => {
		if (n === 0) return '0.000%';
		const p = (n / total) * 100;
		return p < 0.001 ? '<0.001%' : `${p.toFixed(3)}%`;
	};

	console.log(`📄 ${fileName}`);
	console.log(`  • Total entries        : ${total}`);
	console.log(`  • Valid public         : ${counts.public}`);
	console.log(`  • Duplicate public IPs : ${counts.duplicates}`);
	console.log(`  • Removed non-public   : ${counts.nonPublic} (${percent(counts.nonPublic)})`);
	console.log(`  • Removed invalid      : ${counts.invalid} (${percent(counts.invalid)})`);
	console.log(`  • Total removed        : ${removed} (${percent(removed)})`);
};

const cleanTextFile = async filePath => {
	try {
		const content = await fs.readFile(filePath, 'utf8');
		const lines = content.split('\n').map(line => line.trim()).filter(Boolean);

		const counts = { public: 0, nonPublic: 0, invalid: 0, duplicates: 0 };
		const seen = new Set();
		const cleaned = [];
		for (const ip of lines) {
			const type = classifyIp(ip);
			if (type === 'public') {
				if (seen.has(ip)) {
					counts.duplicates++;
				} else {
					seen.add(ip);
					cleaned.push(ip);
					counts.public++;
				}
			} else if (type === 'nonPublic') {
				counts.nonPublic++;
			} else {
				counts.invalid++;
			}
		}

		await fs.writeFile(filePath, cleaned.join('\n'), 'utf8');
		logStats(path.basename(filePath), counts);
	} catch (err) {
		if (err.code !== 'ENOENT') throw err;
	}
};

const cleanCsvFile = async filePath => {
	try {
		const counts = { public: 0, nonPublic: 0, invalid: 0 };

		const content = await fs.readFile(filePath, 'utf8');
		const records = parse(content, { columns: true, skip_empty_lines: true });
		const cleaned = records.filter(row => {
			const type = classifyIp(row.IP);
			if (type === 'public') {
				counts.public++;
				return true;
			} else if (type === 'nonPublic') {
				counts.nonPublic++;
			} else {
				counts.invalid++;
			}
			return false;
		});

		if (cleaned.length) {
			const output = stringify(cleaned, { header: true, columns: Object.keys(cleaned[0]) });
			await fs.writeFile(filePath, output, 'utf8');
		} else {
			await fs.writeFile(filePath, '', 'utf8');
		}

		logStats(path.basename(filePath), counts);
	} catch (err) {
		if (err.code !== 'ENOENT') throw err;
	}
};

(async () => {
	await cleanTextFile(FILES.txt);
	console.log();
	await cleanCsvFile(FILES.csv);
})();