package main

import (
	"flag"
	"log"

	"github.com/pkimetal/pkimetal/internal/mtctest"
)

func main() {
	draft06 := flag.Bool("draft06", false, "generate only draft-06 fixtures")
	flag.Parse()
	if *draft06 {
		if err := mtctest.WriteDraft06Fixtures("mtc/testdata"); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := mtctest.WriteGeneratedFixtures("mtc/testdata"); err != nil {
		log.Fatal(err)
	}
}
