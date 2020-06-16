package main

import (
	"html/template"
	"net/http"

	"google.golang.org/appengine"
)

var TestTemplate *template.Template //HTML template to use

func init() {
	http.HandleFunc("/", hello) //main page to display
	http.HandleFunc("/Address", addressTest)
	http.HandleFunc("/PrivateKey", privateKeyTest)
	http.HandleFunc("/VanitySum", vanitySumTest)
	http.HandleFunc("/VanityMult", vanityMultTest)
	http.HandleFunc("/VanityAll", vanityAllTest)
	http.HandleFunc("/Vanity", vanityAddressTest)
	http.HandleFunc("/Brainwallet", brainwalletTest)
	http.HandleFunc("/ProofOfBurn", proofOfBurnTest)

	var err error
	TestTemplate, err = template.ParseFiles("html/GoTestMain.html")

	if err != nil {
		return
	}
}

func main() {
	appengine.Main()
}

func hello(w http.ResponseWriter, r *http.Request) {
	TestTemplate.Execute(w, nil)
}
