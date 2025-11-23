# 📃 Malicious IP Address List
This repository contains a list of IP addresses associated with various malicious activities on the internet.
Many of them belong to botnets or VPN/proxy networks used to carry out attacks, including DDoS and other forms of abuse.
If you find this repository helpful, consider leaving a star. Thank you, have a nice day!

🌍 **A trustworthy whitelist of known bot IP addresses is available at [sefinek/known-bots-ip-whitelist](https://github.com/sefinek/known-bots-ip-whitelist).**  
📑 **For solid and effective Cloudflare WAF rules, check out [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions).**

> [!TIP]
> Looking for a better alternative? Visit [sniffcat.com](https://sniffcat.com) — a new and efficient alternative to AbuseIPDB.
> The service provides detailed reports on malicious IP addresses and offers filtering by confidence score, countries, categories, and IP version.
> Data can be downloaded in JSON or TXT format and is regularly updated based on submissions from our users. Results are generated automatically and available completely free of charge!  
> You can find the documentation [here](https://sniffcat.com/documentation/api/blacklist).


## What can this list block?
1. ✅ DDoS attacks (L7 – HTTP flood)
   - HTTP requests originating from known botnets
   - Traffic with unusual HTTP headers or suspicious endpoints
   - Connections from sources with confirmed malicious activity
   - Requests impersonating real browsers
2. ✅ Malicious bots and crawlers
3. ✅ Bots generating artificial views  
   *(especially useful if you use Google AdSense)*
4. ✅ Malicious VPNs and proxies used for abuse

> [!IMPORTANT]
> Blocking IP addresses should be done carefully to avoid restricting legitimate traffic.  
> Regular updates of the list are recommended.


## Cron
Updates usually occur **every 2 hours**, but sometimes a delay of several days may occur.
If you notice a longer lack of updates, you can report it via an [Issue](https://github.com/sefinek/Malicious-IP-Addresses/issues).
The list is actively maintained and will not be abandoned.


## Available Files
### ✅ TXT (recommended)
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

#### curl
```bash
curl -fsS -o blacklist.csv https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```

#### wget
```bash
wget -nv -O blacklist.csv https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```

> [!IMPORTANT]  
> This file contains user agents, endpoints, and IP addresses that have been blacklisted.
> Not all IP addresses from [main.txt](lists/main.txt) are included in [details.csv](lists/details.csv)!


## MIT License
Copyright © 2024–2025 Sefinek (https://sefinek.net)
