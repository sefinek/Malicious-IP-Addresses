import fs from 'node:fs';
import path, { dirname } from 'node:path';
import { parse } from 'csv-parse';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const LISTS_DIR = path.join(__dirname, 'lists');
const FILES = {
	txt: path.join(LISTS_DIR, 'main.txt'),
	csv: path.join(LISTS_DIR, 'details.csv'),
};
const criteriaMapping = { endpoint: 4, ip: 3, userAgent: 5 };

const removeFromTxt = (filePath, patterns) => {
	if (!fs.existsSync(filePath)) return 0;

	try {
		const originalData = fs.readFileSync(filePath, 'utf8').split('\n');
		const filteredData = originalData.filter(line => !patterns.includes(line.trim()));
		fs.writeFileSync(filePath, filteredData.join('\n'));
		return originalData.length - filteredData.length;
	} catch {
		return 0;
	}
};

const parseCSV = async () => {
	const csvData = [];
	const parser = fs.createReadStream(FILES.csv).pipe(parse({ delimiter: ',' }));

	for await (const record of parser) {
		csvData.push(
			record.map(field => {
				const sanitizedField = field.replace(/"/g, '\'');
				return (/[";, ]/).test(sanitizedField) ? `"${sanitizedField}"` : sanitizedField;
			})
		);
	}

	return csvData;
};

const filterByCriteria = (data, criteria, index) => data.filter(line => line[index]?.includes(criteria));
const removeFromCSV = (data, lines) =>
	data.filter(line => !lines.some(matchingLine =>
		line.length === matchingLine.length && line.every((value, index) => value.trim() === matchingLine[index].trim())
	));

const removeByCriteria = async (criteria, criteriaType) => {
	if (!criteria || !criteriaType) return console.error('Criteria and criteriaType are required parameters.');
	if (!fs.existsSync(FILES.csv)) return console.error('CSV file not found:', FILES.csv);

	try {
		const csvData = await parseCSV();

		const matchingLines = filterByCriteria(csvData, criteria, criteriaMapping[criteriaType]);
		const ipsToRemove = [...new Set(matchingLines.map(line => line[3]))];
		if (ipsToRemove.length) {
			const txtRemovedCount = removeFromTxt(FILES.txt, ipsToRemove);
			const updatedCsvData = removeFromCSV(csvData, matchingLines);
			fs.writeFileSync(FILES.csv, updatedCsvData.map(line => line.join(',')).join('\n'));
			console.log(`-${txtRemovedCount} lines from main.txt | -${matchingLines.length} lines from details.csv`);
		} else {
			console.warn(`No matching ${criteriaType.toUpperCase()} found in CSV for: ${criteria}`);
		}
	} catch (err) {
		console.error(err);
	}
};

(async () => {
	// Remove by user-agent
	// await removeByCriteria('', 'userAgent');

	// Remove by IP
	await removeByCriteria('', 'ip');

	// Remove by endpoint
	// await removeByCriteria('', 'endpoint');
})();