package main

import (
	"fmt"
	"os"
	"strings"
)

var flag = "irisctf{"

func init() {
	runed := []string{}
	z := rune(0)

	for _, v := range flag {
		fmt.Println(string(v))
		fmt.Println(z)
		fmt.Println("------------")
		runed = append(runed, string(v+z))
		z = v
	}

	flag = strings.Join(runed, "")
}

func main() {
	file, err := os.OpenFile("test", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()
	if _, err := file.Write([]byte(flag)); err != nil {
		fmt.Println(err)
		return
	}
}
