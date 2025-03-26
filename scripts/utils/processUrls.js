const axios = require('../services/axios.js');
const fs = require('node:fs');
const path = require('node:path');

module.exports = async (urls, filePath) => {
	try {
		const responses = await Promise.all(urls.map(url => axios.get(url)));
		const content = responses.map(({ data }, index) =>
			`# ${urls[index]}\n${data.prefixes.map(prefix => prefix.ipv4Prefix || prefix.ipv6Prefix).join('\n')}`
		).join('\n\n');

		fs.mkdirSync(path.dirname(filePath), { recursive: true });
		fs.writeFileSync(filePath, content, 'utf-8');
	} catch (err) {
		console.error(err.stack);
	}
};