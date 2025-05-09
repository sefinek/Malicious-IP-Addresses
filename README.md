# 📃 Malicious IP Address List
This repository contains a list of IP addresses associated with various malicious activities on the internet.
Many of them are part of botnets or VPN/proxy networks used to conduct cyberattacks — including DDoS and more.

⭐ **If you find this repository helpful, please consider giving it a star. Thank you!**  
📄 **Looking for solid and effective Cloudflare WAF expressions? Check out [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions)**


## What Can This List Block?
1. ✅ DDoS attacks (L7 – HTTP flood)
    - HTTP requests from known botnets
    - Requests with unusual HTTP headers or URI paths
    - Traffic from known bad sources
    - Requests impersonating real browsers
2. ✅ Malicious bots & crawlers
3. ✅ Bots generating artificial views (useful if you use Google AdSense)
4. ✅ Malicious VPNs & proxies

> [!IMPORTANT]  
> Blocking IP addresses should be done carefully to avoid disrupting legitimate traffic. Regularly updating the list is highly recommended.


## Cron
Updates usually occur every 2 hours, but occasionally there may be a delay of several days. The list is actively maintained and will not be abandoned.


## Available Files
### ✅ TXT (recommended)
```text
https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

#### Download via curl
```bash
curl -L --progress-bar -o main.txt https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

### 📊 CSV
```text
https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```

> [!IMPORTANT]  
> This file contains user agents, endpoints, and IP addresses that have been blacklisted.
> Not all IP addresses from [main.txt](lists/main.txt) are included in [details.csv](lists/details.csv).

#### Download via curl
```bash
curl -L --progress-bar -o details.csv https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/details.csv
```


## Other Repositories
1. [sefinek/Cloudflare-WAF-Rules](https://github.com/sefinek/Cloudflare-WAF-Rules)
2. [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)