package modules

import (
	"flag"
	"fmt"
)

type Options struct {
	targets          *string
	logins           *string
	dir              *string
	clickString      *string
	loginString      *string
	downloadString   *string
	noLogin          *bool
	hasDownload      *bool
	hasLoginMetadata *bool
	hasExecution     *bool
	execution        *string
	report           *bool
	verbose          *bool
}

func ParseOptions() (Options, error) {
	options := Options{
		targets:          flag.String("t", "LISTA_envio_address.csv", "phishing campaign targets DEFAULT=LISTA_envio_address.csv"),
		logins:           flag.String("l", "logins2.log", "phishing campaign logins file DEFAULT=logins2.log"),
		dir:              flag.String("d", "Logs", "phishing log directory DEFAULT=Logs"),
		clickString:      flag.String("c", "GET /?id=", "parameter of the userid DEFAULT:`GET /?id=`"),
		loginString:      flag.String("s", "POST /login_form/login.php", "endpoint of the login: DEFAULT=`POST /login_form/login.php`"),
		downloadString:   flag.String("D", "GET /update_flash_player.zip", "default GET /update_flash_player.zip, if has unique binary try GET /encuestas/encuestas[0-9]+.zip"),
		noLogin:          flag.Bool("nl", false, "phishing without creds"),
		hasDownload:      flag.Bool("hd", false, "phishing with download binaries"),
		hasLoginMetadata: flag.Bool("hl", false, "you inicate the victim id in the post url"),
		hasExecution:     flag.Bool("he", false, "phishing with executed binaries"),
		execution:        flag.String("e", "data.log", "phishing campaign executions logs"),
		report:           flag.Bool("r", false, "generate report csv"),
		verbose:          flag.Bool("v", false, "verbose mode"),
	}

	flag.Usage = func() {
		fmt.Printf("Usage of our Program: \n")
		fmt.Printf("./phishingParser ./phishreport.py -t emailsEmpleados.csv -l ./login.log --login-string 'POST /primer.php' -v\n")
	}

	flag.Parse()
	return options, nil
}
