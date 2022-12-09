package modules

import(
	"os"
	"fmt"
	"bufio"
)

func ReadLines(fileLocation string) ([]string){
	file, err := os.Open(fileLocation)
    if err != nil {
        fmt.Println(err)
    }
    defer file.Close()
 
	namesSlice := make([]string, 0)
	scanner := bufio.NewScanner(file)
	
    for scanner.Scan() {
		namesSlice = append(namesSlice, scanner.Text())
    }

	return namesSlice;
}