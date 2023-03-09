package modules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func ParseLogs(sess *Session) {
	sess.Data.targetHashMap = createTargetHashMapFromTargets(sess)
	apacheLogsMixer(sess)
	sess.Data.clickString = replaceString(*sess.Options.clickString)
	sess.Data.loginString = replaceString(*sess.Options.loginString)
	sess.Data.downloadString = replaceString(*sess.Options.downloadString)
	setAllUsersClicks(sess)
	sess.Data.victimsHashMap = getValidUsersClicks(sess)
	sess.Data.victimsHashMap = getValidUsersLogins(sess)
	if *sess.Options.hasDownload {
		sess.Data.victimsHashMap = getValidUsersDownloads(sess)
	}
	
	sess.Data.emailsOnlyClick,
		sess.Data.emailsLogin,
		sess.Data.emailsDownload,
		sess.Data.ipsOnlyClick,
		sess.Data.ipsLogins,
		sess.Data.ipsDownload,
		sess.Data.useragentsOnlyClick,
		sess.Data.useragentLogins,
		sess.Data.useragentDownload = analyceData(sess)

	cliReport(sess)

}

// key id, value email
func createTargetHashMapFromTargets(sess *Session) map[string]string {
	sess.Out.Info("- Extracting information from targets csv\n")
	targetsHashMap := make(map[string]string)

	var targetsSlice = ReadLines(*sess.Options.dir + "/" + *sess.Options.targets)
	for _, target := range targetsSlice {
		var targetSplitted = strings.Split(target, ",")
		targetsHashMap[targetSplitted[0]] = targetSplitted[1]
	}
	return targetsHashMap
}

func apacheLogsMixer(sess *Session) {
	//TODO implements this func in native go
	if *sess.Options.verbose {
		sess.Out.Info("- Mixing all access logs to " + *sess.Options.dir + "/logfull.txt\n")
	}
	cmd := exec.Command("sh", "-c", "/bin/cat "+*sess.Options.dir+"/*access* > "+*sess.Options.dir+"/logfull.txt")
	err := cmd.Run()

	if err != nil {
		sess.Out.Fatal(err.Error())
	}
}

func replaceString(str string) string {
	var replacedString = strings.Replace(str, "?", "\\?", -1)

	return replacedString
}

func setAllUsersClicks(sess *Session) {
	sess.Out.Info("- Extracting all clicks (valid or invalid ids) to " + *sess.Options.dir + "/logs_clicks.txt\n")

	f, err := os.Create(*sess.Options.dir + "/logs_clicks.txt")
	if err != nil {
		sess.Out.Fatal(err.Error())
	}
	w := bufio.NewWriter(f)

	logsSlice := ReadLines(*sess.Options.dir + "/logfull.txt")
	clickString := &sess.Data.clickString
	regexString := `^.*` + *clickString + `.*$`
	r := regexp.MustCompile(regexString)
	for _, log := range logsSlice {
		if r.MatchString(log) {
			w.WriteString(log + "\n")
			w.Flush()
		}

	}
}

func getValidUsersClicks(sess *Session) map[string]map[string]map[string]string {
	if *sess.Options.verbose {
		sess.Out.Info("- Extracting valid clicks to " + *sess.Options.dir + "/logs_clicksreales.txt\n")
	}

	victims := make(map[string]map[string]map[string]string)

	f, err := os.Create(*sess.Options.dir + "/logs_clicksreales.txt")
	if err != nil {
		//log.Fatal(err)
		sess.Out.Fatal(err.Error())
	}
	w := bufio.NewWriter(f)

	logsClicksSlice := ReadLines(*sess.Options.dir + "/logs_clicks.txt")
	for _, log := range logsClicksSlice {
		for id, _ := range sess.Data.targetHashMap {
			regexString := `(?P<ip>^\S+) \S+ \S+ \[(?P<date>[\w:\/]+)\s[+\-]\d{4}\] "` + sess.Data.clickString + id + ` HTTP\/1\.1" (\d{3}|-) (\d+|-) "-" .*"(?P<useragent>.*)"$`

			r := regexp.MustCompile(regexString)

			if r.MatchString(log) {

				w.WriteString(log + "\n")
				w.Flush()

				//r.FindStringSubmatch()
				res := r.FindAllStringSubmatch(log, -1)
				logInformation := make(map[string]string)
				for i := range res {

					logInformation["ip"] = res[i][1]
					logInformation["date"] = res[i][2]
					logInformation["useragent"] = res[i][5]
				}

				if victims[sess.Data.targetHashMap[id]] == nil {
					victims[sess.Data.targetHashMap[id]] = make(map[string]map[string]string)
				}
				victims[sess.Data.targetHashMap[id]]["access"] = logInformation

			}
		}
	}
	return victims
}

func getValidUsersLogins(sess *Session) map[string]map[string]map[string]string {
	victims := sess.Data.victimsHashMap
	if !*sess.Options.noLogin {
		if *sess.Options.verbose {
			sess.Out.Info("- Extracting only valid logins (valid ids) to " + *sess.Options.dir + "/logs_loginsreales.txt\n")
		}

		realLoginFile, err := os.Create(*sess.Options.dir + "/logs_loginsreales.txt")
		if err != nil {

			sess.Out.Fatal(err.Error())
		}
		loginRealesWriter := bufio.NewWriter(realLoginFile)

		loginLogsSlice := ReadLines(*sess.Options.dir + "/" + *sess.Options.logins)

		for _, log := range loginLogsSlice {

			var logParsed map[string]string
			json.Unmarshal([]byte(log), &logParsed)

			if logParsed["id"] != "" {

				loginRealesWriter.WriteString(log + "\n")
				loginRealesWriter.Flush()

				logInformation := make(map[string]string)
				logInformation["date"] = logParsed["date"]
				if logParsed["username"] != "" {
					logInformation["username"] = logParsed["username"]
				}

				if victims[sess.Data.targetHashMap[logParsed["id"]]] == nil {
					victims[sess.Data.targetHashMap[logParsed["id"]]] = make(map[string]map[string]string)
				}
				victims[sess.Data.targetHashMap[logParsed["id"]]]["login"] = logInformation
			}
		}

		if *sess.Options.hasLoginMetadata {
			realPostFile, err := os.Create(*sess.Options.dir + "/logs_loginsreales.txt")
			if err != nil {

				sess.Out.Fatal(err.Error())
			}
			realPostWriter := bufio.NewWriter(realPostFile)

			apacheLogsSlice := ReadLines(*sess.Options.dir + "/logfull.txt")
			for _, log := range apacheLogsSlice {
				for id, _ := range sess.Data.targetHashMap {
					regexString := `(?P<ip>^\S+) \S+ \S+ \[(?P<date>[\w:\/]+)\s[+\-]\d{4}\] "` + *sess.Options.loginString + id + ` HTTP\/1\.1" (\d{3}|-) (\d+|-) "-" .*"(?P<useragent>.*)"$`
					r := regexp.MustCompile(regexString)
					if r.MatchString(log) {
						realPostWriter.WriteString(log + "\n")
						realPostWriter.Flush()
						logInformation := make(map[string]string)
						res := r.FindAllStringSubmatch(log, -1)
						for i := range res {
							logInformation["ip"] = res[i][1]
							logInformation["date"] = res[i][2]
							logInformation["useragent"] = res[i][5]
						}

						if victims[sess.Data.targetHashMap[id]] == nil {
							victims[sess.Data.targetHashMap[id]] = make(map[string]map[string]string)
						}
						victims[sess.Data.targetHashMap[id]]["login_metadata"] = logInformation
					}

				}
			}
		}

	}
	return victims
}

func getValidUsersDownloads(sess *Session) map[string]map[string]map[string]string {
	if *sess.Options.verbose {
		sess.Out.Info("- Extracting valid downloads to " + *sess.Options.dir + "/logs_downloadsreales.txt\n")
	}

	victims := sess.Data.victimsHashMap

	f, err := os.Create(*sess.Options.dir + "/logs_downloadsreales.txt")
	if err != nil {
		//log.Fatal(err)
		sess.Out.Fatal(err.Error())
	}
	w := bufio.NewWriter(f)

	logsClicksSlice := ReadLines(*sess.Options.dir + "/logfull.txt")
	for _, log := range logsClicksSlice {
		for id, _ := range sess.Data.targetHashMap {
			regexString := `(?P<ip>^\S+) \S+ \S+ \[(?P<date>[\w:\/]+)\s[+\-]\d{4}\] "`+sess.Data.downloadString+` HTTP\/1\.1" [0-9]* [0-9]* ".*\?id=` + id + `" "(?P<useragent>.*)"`
			r := regexp.MustCompile(regexString)

			if r.MatchString(log) {

				w.WriteString(log + "\n")
				w.Flush()

				//r.FindStringSubmatch()
				res := r.FindAllStringSubmatch(log, -1)
				logInformation := make(map[string]string) 
				for i := range res {
					logInformation["ip"] = res[i][1]
					logInformation["date"] = res[i][2]
					logInformation["useragent"] = res[i][3]
				}

				if victims[sess.Data.targetHashMap[id]] == nil {
					victims[sess.Data.targetHashMap[id]] = make(map[string]map[string]string)
				}
				victims[sess.Data.targetHashMap[id]]["download"] = logInformation
			}
		}
	}
	return victims
}

func analyceData(sess *Session) ([]string, []string, []string, map[string]int,map[string]int, map[string]int, map[string]int, map[string]int, map[string]int) {
	if *sess.Options.verbose {
		sess.Out.Info("- Extracting all the information ...\n")
	}

	var emailsOnlyClicks []string
	var emailsLogins []string
	var emailsDownload []string

	var ipsOnlyClick = make(map[string]int)
	var ipsLogins = make(map[string]int)
	var ipsDownload = make(map[string]int)

	var useragentOnlyClick = make(map[string]int)
	var useragentLogins = make(map[string]int)
	var useragentDownload = make(map[string]int)


	

	for email, victim := range sess.Data.victimsHashMap {
		if _, ok := victim["access"]; ok {
		
			if _, ok := victim["login"]; !ok {
				if _, ok := victim["download"]; !ok {
					emailsOnlyClicks = append(emailsOnlyClicks, email)
					ipsOnlyClick[victim["access"]["ip"]]++
					useragentOnlyClick[victim["access"]["useragent"]]++
				}
			} 
			if _, ok := victim["download"]; ok{
				emailsDownload = append(emailsDownload, email)
				ipsDownload[victim["download"]["ip"]]++
				useragentDownload[victim["download"]["useragent"]]++
			} 
			if _, ok := victim["login"]; ok{
				emailsLogins = append(emailsLogins, email)
				ipsLogins[victim["access"]["ip"]]++
				useragentLogins[victim["access"]["useragent"]]++
			}
		}
	}

	sess.Data.totalEmployees = float64(len(sess.Data.targetHashMap))
	
	sess.Data.clickPercentage = (float64(len(emailsOnlyClicks)) * float64(100)) / sess.Data.totalEmployees
	sess.Data.loginPercentage = (float64(len(emailsLogins)) * float64(100)) / sess.Data.totalEmployees
	sess.Data.downloadPercentage = (float64(len(emailsDownload)) * float64(100)) / sess.Data.totalEmployees
	sess.Data.afectedPercentage = sess.Data.clickPercentage + sess.Data.loginPercentage + sess.Data.downloadPercentage
	sess.Data.nonAfectedPercentage = float64(100) - sess.Data.afectedPercentage

	return emailsOnlyClicks, emailsLogins, emailsDownload, ipsOnlyClick, ipsLogins, ipsDownload, useragentOnlyClick, useragentLogins, useragentDownload
}

func cliReport(sess *Session) {
	//if *sess.Options.verbose {
	//	sess.Out.Info("- Report:\n")
	//	victimsJson, err := json.Marshal(sess.Data.victimsHashMap)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	fmt.Println(string(victimsJson))
	//}
	printPercentage(sess)
	printEmailsInfo(sess)
	printIPsInfo(sess)
	printUserAgentsInfo(sess)
}

func printPercentage(sess *Session) {
	fmt.Println("TOTAL_EMPLOYEES", sess.Data.totalEmployees)
	fmt.Println("# Percentages")
	fmt.Println("AFFECTED", sess.Data.afectedPercentage,"%")
	fmt.Println("NON_AFFECTED", sess.Data.nonAfectedPercentage)
	fmt.Println("ONLY_CLICK", sess.Data.clickPercentage,"%")
	fmt.Println("LOGIN", sess.Data.loginPercentage,"%")
	fmt.Println("DOWNLOAD", sess.Data.downloadPercentage,"%")
}

func printEmailsInfo(sess *Session) {
	fmt.Println("# Emails")
	printEmailsOnlyClick(sess)
	printEmailsLogin(sess)
	printEmailsDownload(sess)
}
func printEmailsOnlyClick(sess *Session) {
	fmt.Println("## Emails only click")
	fmt.Println("TOTAL_EMAILS_ONLY_CLICK ", len(sess.Data.emailsOnlyClick))
	for _, email := range sess.Data.emailsOnlyClick {
		fmt.Println("EMAIL_CLICK " + email)
	}
}
func printEmailsLogin(sess *Session) {
	fmt.Println("## Emails with login")
	fmt.Println("TOTAL_EMAILS_LOGIN ", len(sess.Data.emailsLogin))
	for _, email := range sess.Data.emailsLogin {
		fmt.Println("EMAIL_LOGIN " + email)
	}
}
func printEmailsDownload(sess *Session) {
	fmt.Println("## Emails with download")
	fmt.Println("TOTAL_EMAILS_DOWNLOAD ", len(sess.Data.emailsDownload))
	for _, email := range sess.Data.emailsDownload {
		fmt.Println("EMAIL_DOWNLOAD " + email)
	}
}

func printIPsInfo(sess *Session) {
	fmt.Println("# IPs")
	printIPsOnlyClick(sess)
	printIPsLogin(sess)
	printIPsDownload(sess)
}
func printIPsOnlyClick(sess *Session) {
	fmt.Println("## IPs only click")
	fmt.Println("TOTAL_IPs_ONLY_CLICK ", len(sess.Data.ipsOnlyClick))
	for ip, count := range sess.Data.ipsOnlyClick {
		fmt.Println("IP_CLICK ", ip, "TOTAL ", count)
	}
}
func printIPsLogin(sess *Session) {
	fmt.Println("## IPs logins")
	fmt.Println("TOTAL_IPs_LOGINS ", len(sess.Data.ipsLogins))
	for ip, count := range sess.Data.ipsLogins {
		fmt.Println("IP_LOGIN ", ip, "TOTAL ", count)
	}
}
func printIPsDownload(sess *Session) {
	fmt.Println("## IPs download")
	fmt.Println("TOTAL_IPs_DOWNLOADS ", len(sess.Data.ipsDownload))
	for ip, count := range sess.Data.ipsDownload {
		fmt.Println("IP_DOWNLOAD ", ip, "TOTAL ", count)
	}
}

func printUserAgentsInfo(sess *Session) {
	fmt.Println("# USER AGENTS")
	printUserAgentOnlyClick(sess)
	printUserAgentsLogin(sess)
	printUserAgentsDownload(sess)
}
func printUserAgentOnlyClick(sess *Session) {
	fmt.Println("## USER AGENT only click")
	fmt.Println("TOTAL_USER_AGENT_ONLY_CLICK ", len(sess.Data.useragentsOnlyClick))
	for ip, count := range sess.Data.useragentsOnlyClick {
		fmt.Println("USER_AGENT_CLICK ", ip, "TOTAL ", count)
	}
}
func printUserAgentsLogin(sess *Session) {
	fmt.Println("## USER AGENT logins")
	fmt.Println("TOTAL_USER_AGENT_LOGINS ", len(sess.Data.useragentLogins))
	for ip, count := range sess.Data.useragentLogins {
		fmt.Println("USER_AGENT_LOGIN ", ip, "TOTAL ", count)
	}
}
func printUserAgentsDownload(sess *Session) {
	fmt.Println("## USER AGENT download")
	fmt.Println("TOTAL_USER_AGENT_DOWNLOAD ", len(sess.Data.useragentDownload))
	for ip, count := range sess.Data.useragentDownload {
		fmt.Println("USER_AGENT_DOWNLOAD ", ip, "TOTAL ", count)
	}
}
