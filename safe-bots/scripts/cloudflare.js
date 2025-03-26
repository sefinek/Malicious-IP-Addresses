const axios = require('../../scripts/services/axios.js');
const fs = require('node:fs');
const path = require('node:path');

const URLS = [
	'https://www.cloudflare.com/ips-v4',
	'https://www.cloudflare.com/ips-v6',
];

const FILE_PATH = path.resolve(__dirname, '..', 'actions', 'safe-bots', 'cloudflare.txt');

(async () => {
	try {
		const responses = await Promise.all(URLS.map(link => axios.get(link)));
		const content = responses.map((response, index) => `# ${URLS[index]}\n${response.data}`).join('\n\n');

		fs.mkdirSync(path.dirname(FILE_PATH), { recursive: true });
		fs.writeFileSync(FILE_PATH, content, 'utf-8');
	} catch (err) {
		console.error(err.stack);
	}
})();