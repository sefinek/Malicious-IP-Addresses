const fs = require('node:fs');
const path = require('node:path');
const ipaddr = require('ipaddr.js');
const axios = require('./services/axios.js');

const WHITELISTS = [
	'https://raw.githubusercontent.com/AnTheMaker/GoodBots/main/all.ips',
];

const fetchAllWhitelists = async () => {
	try {
		const allIPs = await Promise.all(WHITELISTS.map(async url => {
			console.log(`Fetching whitelist from: ${url}`);
			const response = await axios.get(url);
			if (response.status !== 200) throw new Error(`Request Failed. Status Code: ${response.status}`);

			return response.data.split('\n').filter(ip => ip.trim() !== '' && !ip.startsWith('#'));
		}));

		const uniqueIPs = [...new Set(allIPs.flat())];
		console.log(`Total unique IPs fetched: ${uniqueIPs.length}`);
		return uniqueIPs;
	} catch (err) {
		console.error(`Failed to fetch whitelists: ${err.stack}`);
		return [];
	}
};

const isWhitelisted = (ip, whitelistedIPsSet) => {
	try {
		const parsedIP = ipaddr.parse(ip);
		if (whitelistedIPsSet.has(ip)) {
			console.log(`IP ${ip} is directly whitelisted.`);
			return true;
		}

		for (const whitelistedIP of whitelistedIPsSet) {
			if (whitelistedIP.includes('/')) {
				const range = ipaddr.parseCIDR(whitelistedIP);
				if (parsedIP.kind() === range[0].kind() && parsedIP.match(range)) {
					console.log(`IP ${ip} matches CIDR range ${whitelistedIP}`);
					return true;
				}
			}
		}
	} catch (err) {
		console.warn(`Error checking if IP ${ip} is whitelisted: ${err.message}`);
		return false;
	}
	return false;
};

const removeIPsFromFile = (filePath, whitelistedIPs) => {
	console.log(`Processing file: ${filePath}`);
	const whitelistedIPsSet = new Set(whitelistedIPs);
	const content = fs.readFileSync(filePath, 'utf8');
	const lines = content.split('\n').filter(line => line.trim() !== '');
	const ext = path.extname(filePath);
	let filteredLines = [];
	const initialCount = lines.length;

	if (ext === '.txt') {
		filteredLines = lines.filter(line => {
			const ip = line.trim();
			const isWhite = isWhitelisted(ip, whitelistedIPsSet);
			if (isWhite) console.log(`Removing whitelisted IP (${ip})...`);
			return !isWhite;
		});
	} else if (ext === '.csv') {
		const [header, ...rest] = lines;
		filteredLines = [header, ...rest.filter(line => {
			const fields = line.split(',');
			if (fields.length > 3) {
				const ip = fields[3].trim();
				const isWhite = isWhitelisted(ip, whitelistedIPsSet);
				if (isWhite) console.log(`Removing whitelisted IP (${ip}) from CSV...`);
				return !isWhite;
			}
			return true;
		})];
	}

	const filteredCount = filteredLines.length;
	if (filteredLines.length > 0 && filteredLines[filteredLines.length - 1] === '') {
		filteredLines.pop();
	}

	fs.writeFileSync(filePath, filteredLines.join('\n').trim(), 'utf8');
	console.log(`${filePath}: Initial entries: ${initialCount}; Removed: ${initialCount - filteredCount}; Remaining: ${filteredCount}`);
};

(async () => {
	const filesToProcess = [
		path.join(__dirname, '..', 'lists', 'details.csv'),
		path.join(__dirname, '..', 'lists', 'main.txt'),
	];

	try {
		console.log('Starting IP processing...');
		const whitelistedIPs = await fetchAllWhitelists();
		if (whitelistedIPs.length === 0) {
			console.log('No whitelisted IPs found, skipping processing.');
			return;
		}

		for (const filePath of filesToProcess) {
			removeIPsFromFile(filePath, whitelistedIPs);
		}
	} catch (err) {
		console.error('Error during processing:', err);
	}
})();
