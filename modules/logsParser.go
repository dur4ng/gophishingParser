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
	sess.Data.targetHashMap = createTargeHashMapFromTargets(sess)
	apacheLogsMixer(sess)
	sess.Data.clickString = replaceString(*sess.Options.clickString)
	sess.Data.loginString = replaceString(*sess.Options.loginString)
	setAllUsersClicks(sess)
	sess.Data.victimsHashMap = getValidUsersClicks(sess)
	sess.Data.victimsHashMap = getValidUsersLogins(sess)

	sess.Data.emailsOnlyClick,
		sess.Data.emailsLogin,
		sess.Data.ipsOnlyClick,
		sess.Data.ipsLogins,
		sess.Data.useragentsOnlyClick,
		sess.Data.useragentLogins = analyceData(sess)

	cliReport(sess)

}

func createTargeHashMapFromTargets(sess *Session) map[string]string {
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
				logInformation["username"] = logParsed["username"]

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

func analyceData(sess *Session) ([]string, []string, map[string]int, map[string]int, map[string]int, map[string]int) {
	if *sess.Options.verbose {
		sess.Out.Info("- Extracting all the information ...\n")
	}
	var emailsOnlyClicks []string
	var emailsLogins []string
	var ipsOnlyClick = make(map[string]int)
	var ipsLogins = make(map[string]int)
	var useragentOnlyClick = make(map[string]int)
	var useragentLogins = make(map[string]int)

	for email, victim := range sess.Data.victimsHashMap {
		var ip string = victim["access"]["ip"]
		var useragent string = victim["access"]["useragent"]

		if _, ok := victim["access"]; ok {
			if _, ok := victim["login"]; !ok {
				emailsOnlyClicks = append(emailsOnlyClicks, email)
				ipsOnlyClick[ip]++
				useragentOnlyClick[useragent]++

			} else {
				emailsLogins = append(emailsLogins, email)
				ipsLogins[ip]++
				useragentLogins[useragent]++
			}
		}
	}

	return emailsOnlyClicks, emailsLogins, ipsOnlyClick, ipsLogins, useragentOnlyClick, useragentLogins
}

func cliReport(sess *Session) {
	if *sess.Options.verbose {
		sess.Out.Info("- Report:\n")
	}
	printEmailsInfo(sess)
	printIPsInfo(sess)
	printUserAgentsInfo(sess)
}

func printEmailsInfo(sess *Session) {
	fmt.Println("# Emails")
	printEmailsOnlyClick(sess)
	printEmailsLogin(sess)
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

func printIPsInfo(sess *Session) {
	fmt.Println("# IPs")
	printIPsOnlyClick(sess)
	printIPsLogin(sess)
}

func printIPsOnlyClick(sess *Session) {
	fmt.Println("## IPs only click")
	fmt.Println("TOTAL_IPs_ONLY_CLICK ", len(sess.Data.ipsOnlyClick))
	for ip, count := range sess.Data.ipsOnlyClick {
		fmt.Println("IP_CLICK ", ip, "TOTAL_CLICKS ", count)
	}
}
func printIPsLogin(sess *Session) {
	fmt.Println("## IPs logins")
	fmt.Println("TOTAL_IPs_LOGINS ", len(sess.Data.ipsLogins))
	for ip, count := range sess.Data.ipsLogins {
		fmt.Println("IP_LOGIN ", ip, "TOTAL_CLICKS ", count)
	}
}

func printUserAgentsInfo(sess *Session) {
	fmt.Println("# USER AGENTS")
	printUserAgentOnlyClick(sess)
	printUserAgentsLogin(sess)
}

func printUserAgentOnlyClick(sess *Session) {
	fmt.Println("## USER AGENT only click")
	fmt.Println("TOTAL_USER_AGENT_ONLY_CLICK ", len(sess.Data.useragentsOnlyClick))
	for ip, count := range sess.Data.useragentsOnlyClick {
		fmt.Println("USER_AGENT_CLICK ", ip, "TOTAL_CLICKS ", count)
	}
}

func printUserAgentsLogin(sess *Session) {
	fmt.Println("## USER AGENT logins")
	fmt.Println("TOTAL_USER_AGENT_LOGINS ", len(sess.Data.useragentsOnlyClick))
	for ip, count := range sess.Data.useragentsOnlyClick {
		fmt.Println("USER_AGENT_LOGIN ", ip, "TOTAL_CLICKS ", count)
	}
}
