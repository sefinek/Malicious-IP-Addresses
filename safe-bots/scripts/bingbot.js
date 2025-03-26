const processUrls = require('../../scripts/utils/processUrls.js');
const path = require('node:path');

const URLS = [
	'https://www.bing.com/toolbox/bingbot.json',
];

const FILE_PATH = path.resolve(__dirname, '..', 'actions', 'safe-bots', 'bingbot.txt');

(async () => {
	await processUrls(URLS, FILE_PATH);
})();