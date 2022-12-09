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
./phishingParser ./phishreport.py -t emailsEmpleados.csv -l ./login.log --login-string 'POST /primer.php' -v
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

## Data
victim data example:
```
example@email.com:map[
    access:map[
        date:28/Nov/2022:09:51:56 
        ip:127.0.0.1
        useragent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56
    ] 
    login:map[
        date:2022-11-28 09:52:33 
        username:example@email.com
    ] 
    login_metadata:map[
            date:28/Nov/2022:09:51:56 
            ip:127.0.0.1 useragent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.56
    ]
]
```
