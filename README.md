# PhishingParser

## Install

## Usage

```

	__________.__    .__       .__    .__                 __________
	\______   \  |__ |__| _____|  |__ |__| ____    ____   \______   \_____ _______  ______ ___________
	 |     ___/  |  \|  |/  ___/  |  \|  |/    \  / ___\   |     ___/\__  \\_  __ \/  ___// __ \_  __ \
	 |    |   |   Y  \  |\___ \|   Y  \  |   |  \/ /_/  >  |    |     / __ \|  | \/\___ \\  ___/|  | \/
	 |____|   |___|  /__/____  >___|  /__|___|  /\___  /   |____|    (____  /__|  /____  >\___  >__|
	               \/        \/     \/        \//_____/                   \/           \/     \/

Usage of our Program:
./gophishingParser -t emailsEmpleados.csv -l ./login.log --login-string 'POST /primer.php' -v
./gophishingParser -d ./Logs -t emailsEmpleados.csv -l ./login.log -s 'POST /primer.php' -hd -D 'GET \/encuestas.zip' -v
```

## Queries to the grepeable output

- Count of emails that only click the malicius link: `cat ./report.txt | grep "TOTAL_EMAILS_ONLY_CLICK" | awk '{ print $2}'`
- List of all emails that only click the malicius link: `cat ./report.txt | grep "EMAIL_CLICK" | awk '{ print $2}'`
- TOTAL_EMAILS_LOGIN
- EMAIL_LOGIN
- TOTAL_IPs_ONLY_CLICK
- IP_CLICK
- TOTAL_IPs_LOGINS
- IP_LOGIN
- TOTAL_USER_AGENT_ONLY_CLICK
- USER_AGENT_CLICK
- TOTAL_USER_AGENT_LOGINS
- USER_AGENT_LOGIN

## TODO

- save out grepeable report into a file
- analytics of user agents: identify device(pc,movil), percentages, ...
- analytics of ips: ASN, provider, owner, percentages,...
