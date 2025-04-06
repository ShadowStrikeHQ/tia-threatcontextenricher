# tia-ThreatContextEnricher
A command-line tool that takes a single IP address, domain, or hash as input and enriches it with publicly available context from VirusTotal's free API (limited lookups), providing a concise summary of known threats and classifications. - Focused on Aggregates threat intelligence feeds from various open-source platforms (e.g., VirusTotal, AbuseIPDB, AlienVault OTX) to correlate indicators of compromise (IOCs) like IPs, domains, and hashes, enabling proactive threat detection. Focuses on simple API integrations and data normalization.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-threatcontextenricher`

## Usage
`./tia-threatcontextenricher [params]`

## Parameters
- `-h`: Show help message and exit
- `-k`: VirusTotal API key. Can also be set via environment variable VIRUSTOTAL_API_KEY.
- `-o`: No description provided

## License
Copyright (c) ShadowStrikeHQ
