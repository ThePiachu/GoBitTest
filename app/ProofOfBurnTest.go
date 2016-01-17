package app

import (
	"appengine"
	"github.com/ThePiachu/Go/mymath"
	"html/template"
	"net/http"
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
	c.Infof("proofOfBurnTest")
	root := r.FormValue("Root")
	filler := r.FormValue("Filler")
	c.Infof("proofOfBurnTest - %v, %v", root, filler)
	if root != "" && filler != "" {
		pob := ProofOfBurnDat{}
		pob.AddressRoot = root
		pob.AddressFiller = string(filler[0])
		address, err := mymath.GenerateProofOfBurnAddress(root, byte(filler[0]))
		if err != nil {
			c.Infof("proofOfBurnTest err - %v", err)
			pob.Error = err.Error()
		}
		pob.ProofOfBurnAddress = address

		ProofOfBurnTestTemplate.Execute(w, pob)
		return
	}

	ProofOfBurnTestTemplate.Execute(w, DefaultPoBDat)
}
