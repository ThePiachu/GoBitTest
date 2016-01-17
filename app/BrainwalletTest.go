package app

import (
	"github.com/ThePiachu/Go/mymath"
	"html/template"
	"net/http"
)

type BrainwalletDat struct {
	Error string

	Passphrase string
	PrivateKey string
	Address    string
}

var BrainwalletTestTemplate *template.Template //HTML template to use
var DefaultWallet BrainwalletDat

func init() {

	var err error
	BrainwalletTestTemplate, err = template.ParseFiles("html/BrainwalletTest.html")

	if err != nil {
		return
	}

	DefaultWallet.Passphrase = "correct horse battery staple"
	DefaultWallet.PrivateKey = "C4BBCB1FBEC99D65BF59D85C8CB62EE2DB963F0FE106F483D9AFA73BD4E39A8A"
	DefaultWallet.Address = "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"

}

func brainwalletTest(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("passphrase") != "" {
		var data BrainwalletDat
		data.Passphrase = r.FormValue("passphrase")
		data.PrivateKey = mymath.Hex2Str(mymath.SingleSHA(mymath.ASCII2Hex(data.Passphrase)))

		address, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(data.PrivateKey))

		data.Address = string(address.Base)
		BrainwalletTestTemplate.Execute(w, data)
		return
	}
	BrainwalletTestTemplate.Execute(w, DefaultWallet)
}
