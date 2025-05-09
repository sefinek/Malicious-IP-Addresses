# 📃 Malicious IP Address List
This repository contains a list of IP addresses associated with various malicious activities on the internet.
Many of these addresses are part of botnets, VPN/Proxy networks used to carry out cyberattacks, such as DDoS attacks, and more.

⭐ **If you find this repository helpful, please consider giving it a star. Thank you!**  
📄 **Looking for solid and effective Cloudflare WAF Expressions? Check out [sefinek/Cloudflare-WAF-Expressions](https://github.com/sefinek/Cloudflare-WAF-Expressions)**

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
The list is usually updated every 2 hours.

## TXT
```text
https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt
```

## CSV
This file contains user agents, endpoints, and IP addresses that have been blacklisted.
Not all IP addresses from [main.txt](lists/main.txt) are included in [details.csv](lists/details.csv).

## Other Repositories
1. [sefinek/Cloudflare-WAF-Rules](https://github.com/sefinek/Cloudflare-WAF-Rules)
2. [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)