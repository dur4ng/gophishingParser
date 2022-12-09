package modules

type Session struct {
	Options Options
	Data    Data
	Out     *Logger
}

type Data struct {
	targetHashMap       map[string]string
	victimsHashMap      map[string]map[string]map[string]string
	emailsOnlyClick     []string
	emailsLogin         []string
	ipsOnlyClick        map[string]int
	ipsLogins           map[string]int
	useragentsOnlyClick map[string]int
	useragentLogins     map[string]int
	clickString         string
	loginString         string
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
