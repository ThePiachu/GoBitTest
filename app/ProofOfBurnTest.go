package main

import (
	"html/template"
	"net/http"

	"google.golang.org/appengine"

	"github.com/ThePiachu/Go/Log"
	"github.com/ThePiachu/Go/mymath"
)

type ProofOfBurnDat struct {
	Error string

	AddressRoot   string
	AddressFiller string

	ProofOfBurnAddress string
}

var DefaultPoBDat ProofOfBurnDat

var ProofOfBurnTestTemplate *template.Template //HTML template to use

func init() {

	var err error
	ProofOfBurnTestTemplate, err = template.ParseFiles("html/ProofOfBurnTest.html")

	if err != nil {
		return
	}

	DefaultPoBDat.AddressRoot = "1Test"
	DefaultPoBDat.AddressFiller = "x"
	DefaultPoBDat.ProofOfBurnAddress = "1TestxxxxxxxxxxxxxxxxxxxxxxzoXNkw"
}

func proofOfBurnTest(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	Log.Infof(c, "proofOfBurnTest")
	root := r.FormValue("Root")
	filler := r.FormValue("Filler")
	Log.Infof(c, "proofOfBurnTest - %v, %v", root, filler)
	if root != "" && filler != "" {
		pob := ProofOfBurnDat{}
		pob.AddressRoot = root
		pob.AddressFiller = string(filler[0])
		address, err := mymath.GenerateProofOfBurnAddress(root, byte(filler[0]))
		if err != nil {
			Log.Infof(c, "proofOfBurnTest err - %v", err)
			pob.Error = err.Error()
		}
		pob.ProofOfBurnAddress = address

		ProofOfBurnTestTemplate.Execute(w, pob)
		return
	}

	ProofOfBurnTestTemplate.Execute(w, DefaultPoBDat)
}
