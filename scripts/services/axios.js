const axios = require('axios');
const { version } = require('../../package.json');

const api = axios.create({
	timeout: 25000,
	headers: {
		'User-Agent': `Mozilla/5.0 (compatible; Malicious-IP-Addresses/${version}; +https://github.com/sefinek/Malicious-IP-Addresses)`,
		'Accept': 'application/json',
		'Cache-Control': 'no-cache',
		'Connection': 'keep-alive',
	},
});

module.exports = api;