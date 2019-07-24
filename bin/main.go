package main

import (
	"os"
	"log"
	_ "plugin"

	testplugin ".."
)

const (
	lib1 = `testlib/testlib.so`
	lib2 = `testlib/testlib2.so`
)


func main() {
	pg2, err := testplugin.Open(lib2)
	if err != nil {
		log.Fatal(err)
	}


	syms := os.Args[1:]
	for _, s := range syms {
		if sym, err := pg2.Lookup(s); err != nil {
			log.Printf("Failed to find symbol %s: %v\n", s, err)
		} else {
			log.Printf("Symbol %+v\n", sym)
		}
	}

	log.Println("All good")
}
