# 🤬 Malicious IP Address List
This repository contains a list of IP addresses associated with various types of malicious activity on the internet.
Many of them belong to botnets or VPN/proxy networks used to carry out attacks, including DDoS attacks and other forms of abuse.
If you find this repository useful, consider leaving a star. Thank you, and have a nice day!

🌍 **A trustworthy whitelist of known bot IP addresses is available at [sefinek/known-bots-ip-whitelist](https://github.com/sefinek/known-bots-ip-whitelist).**  
📑 **For solid and effective Cloudflare WAF rules, check out [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions).**

> [!IMPORTANT]
> IP ADDRESSES ON THIS LIST ARE GENERALLY NOT REMOVED, SO UNDER NO CIRCUMSTANCES SHOULD THIS LIST BE USED TO BLOCK TRAFFIC, E.G., AT THE FIREWALL LEVEL!
> THIS LIST IS INTENDED SOLELY AS A SOURCE OF REPUTATION INFORMATION FOR SPECIFIC IP ADDRESSES. THE PRESENCE OF AN IP ADDRESS ON THIS LIST DOES NOT MEAN THAT IT IS CURRENTLY MALICIOUS OR THAT IT SHOULD BE AUTOMATICALLY BLOCKED. THIS INFORMATION SHOULD BE TREATED AS ONE OF THE FACTORS USED IN RISK ASSESSMENT.
> IF YOU ARE LOOKING FOR A LIST INTENDED FOR TRAFFIC BLOCKING, VISIT [sniffcat.com](https://sniffcat.com) - A MODERN ALTERNATIVE TO ABUSEIPDB.
> SNIFFCAT PROVIDES DETAILED REPORTS ON MALICIOUS IP ADDRESS ACTIVITY AND ALLOWS FILTERING BY CONFIDENCE LEVEL, COUNTRY, CATEGORY, AND OTHER CRITERIA.
> DATA CAN BE RETRIEVED IN JSON OR TXT FORMAT. IT IS REGULARLY UPDATED BASED ON REPORTS FROM OUR USERS. THE LISTS ARE GENERATED AUTOMATICALLY AND ARE COMPLETELY FREE TO USE.
> DOCUMENTATION IS AVAILABLE [AT THIS LINK](https://sniffcat.com/documentation/api/blacklist).

Have questions or need help? Create a [new issue](https://github.com/sefinek/Malicious-IP-Addresses/issues) or join [my Discord server](https://discord.gg/S7NDzCzQTg).
I also post important updates and announcements there. My email address: contact@sefinek.net 😉


## What types of activity does this list cover?
1. ✅ DDoS attacks (L7 - HTTP request flooding)
   - HTTP requests originating from known botnets
   - Traffic with unusual HTTP headers or requests targeting suspicious endpoints
   - Connections from sources with confirmed malicious activity
   - Requests impersonating legitimate web browsers
2. ✅ Malicious bots and crawlers
3. ✅ Bots generating artificial page views *(especially useful if you use Google AdSense)*
4. ✅ IP addresses belonging to VPN networks and proxy servers used for abuse


## Cron
The list is usually updated **every 2 hours**, but delays of several days may occasionally occur.
If you notice that updates have been missing for a longer period, you can report it by creating a [new issue](https://github.com/sefinek/Malicious-IP-Addresses/issues).
The list is actively maintained.


## Available files
### 📄 TXT (recommended)
```text
https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

#### curl
```bash
curl -fsS -o blacklist.txt https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

#### wget
```bash
wget -nv -O blacklist.txt https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

### 📊 CSV
```text
https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```

> [!IMPORTANT]
> This file contains User-Agent values, endpoints, and IP addresses associated with malicious activity.
> The [details.csv](lists/details.csv) file does not contain all IP addresses from [main.txt](lists/main.txt)!

#### curl
```bash
curl -fsS -o blacklist.csv https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```

#### wget
```bash
wget -nv -O blacklist.csv https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```


## MIT License
Copyright © 2024-2026 [Sefinek](https://sefinek.net)