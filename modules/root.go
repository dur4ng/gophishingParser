package modules

import (
	"fmt"
	"os"
	"time"
)

var (
	sess *Session
	err  error
)

func Root() {
	fmt.Print(`
	__________.__    .__       .__    .__                 __________                                   
	\______   \  |__ |__| _____|  |__ |__| ____    ____   \______   \_____ _______  ______ ___________ 
	 |     ___/  |  \|  |/  ___/  |  \|  |/    \  / ___\   |     ___/\__  \\_  __ \/  ___// __ \_  __ \
	 |    |   |   Y  \  |\___ \|   Y  \  |   |  \/ /_/  >  |    |     / __ \|  | \/\___ \\  ___/|  | \/
	 |____|   |___|  /__/____  >___|  /__|___|  /\___  /   |____|    (____  /__|  /____  >\___  >__|   
	               \/        \/     \/        \//_____/                   \/           \/     \/       
	`)

	fmt.Println("Time:", time.Now())

	if sess, err = NewSession(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//TODO checks

	ParseLogs(sess)
}
