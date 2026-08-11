package main

import (
	"log"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

func main() {
	if err := mtctest.WriteGeneratedFixtures("mtc/testdata"); err != nil {
		log.Fatal(err)
	}
}
