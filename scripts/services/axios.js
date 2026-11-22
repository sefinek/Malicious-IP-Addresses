import axios from 'axios';
import pkg from '../../package.json' with { type: 'json' };

const api = axios.create({
	timeout: 25000,
	headers: {
		'User-Agent': `Mozilla/5.0 (compatible; Malicious-IP-Addresses/${pkg.version}; +${pkg.homepage})`,
		'Accept': 'application/json',
		'Cache-Control': 'no-cache',
		'Connection': 'keep-alive',
	},
});

export default api;