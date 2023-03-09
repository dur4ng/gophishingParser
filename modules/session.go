package modules

type Session struct {
	Options Options
	Data    Data
	Out     *Logger
}

type Data struct {
	clickString         string
	loginString         string
	downloadString string

	targetHashMap       map[string]string
	victimsHashMap      map[string]map[string]map[string]string

	emailsOnlyClick     []string
	emailsLogin         []string
	emailsDownload 		[]string

	ipsOnlyClick        map[string]int
	ipsLogins           map[string]int
	ipsDownload 		map[string]int
	useragentsOnlyClick map[string]int
	useragentLogins     map[string]int
	useragentDownload   map[string]int

	totalEmployees float64
	afectedPercentage float64
	nonAfectedPercentage float64
	clickPercentage float64
	loginPercentage float64
	downloadPercentage float64
	
}

func (s *Session) Start() {
	s.initLogger()
	s.initLogParser()
}

func (s *Session) initLogParser() {}

func (s *Session) initLogger() {
	s.Out = &Logger{}
}
func NewSession() (*Session, error) {
	var err error
	var session Session

	if session.Options, err = ParseOptions(); err != nil {
		return nil, err
	}

	session.Start()

	return &session, nil
}
