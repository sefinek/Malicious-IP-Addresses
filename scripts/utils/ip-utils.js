import ipaddr from 'ipaddr.js';

/**
 * Set of IP ranges that are not publicly routable.
 */
export const NON_PUBLIC_RANGES = new Set([
	'unspecified', 'multicast', 'linkLocal', 'loopback', 'reserved', 'benchmarking',
	'amt', 'broadcast', 'carrierGradeNat', 'private', 'as112', 'uniqueLocal',
	'ipv4Mapped', 'rfc6145', '6to4', 'teredo', 'as112v6', 'orchid2', 'droneRemoteIdProtocolEntityTags',
]);

/**
 * Classifies an IP address as public, non-public, or invalid.
 * @param {string} ip - The IP address to classify
 * @returns {'public'|'nonPublic'|'invalid'} The classification
 */
export const classifyIp = ip => {
	if (!ip || !ipaddr.isValid(ip)) return 'invalid';
	const range = ipaddr.parse(ip).range();
	return NON_PUBLIC_RANGES.has(range) ? 'nonPublic' : 'public';
};

/**
 * Compares two IP addresses for sorting.
 * Supports both IPv4 and IPv6 addresses.
 * @param {string} ipA - First IP address
 * @param {string} ipB - Second IP address
 * @returns {number} Comparison result (-1, 0, or 1)
 */
export const compareIps = (ipA, ipB) => {
	try {
		const parsedA = ipaddr.parse(ipA);
		const parsedB = ipaddr.parse(ipB);
		const bytesA = parsedA.toByteArray();
		const bytesB = parsedB.toByteArray();

		for (let i = 0; i < Math.max(bytesA.length, bytesB.length); i++) {
			const diff = (bytesA[i] || 0) - (bytesB[i] || 0);
			if (diff !== 0) return diff;
		}
		return 0;
	} catch {
		return ipA.localeCompare(ipB);
	}
};
