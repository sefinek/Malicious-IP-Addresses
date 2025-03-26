const axios = require('axios');
const { version } = require('../../package.json');

axios.defaults.headers.common = {
	'User-Agent': `Mozilla/5.0 (compatible; Malicious-IP-Addresses/${version}; +https://github.com/sefinek/Malicious-IP-Addresses)`,
	'Accept': 'application/json',
	'Content-Type': 'application/json',
	'Accept-Encoding': 'gzip, deflate, br',
	'Accept-Language': 'pl;q=0.9',
	'Cache-Control': 'no-cache',
	'Connection': 'keep-alive',
};

axios.defaults.timeout = 25000;

module.exports = axios;