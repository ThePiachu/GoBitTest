package main

import (
	"fmt"
	"github.com/ThePiachu/Go/mymath"
	"html/template"
	"math"
	"net/http"
)

var VanityAddressTestTemplate *template.Template //HTML template to use

var DefaultVanityAddressData VanityAddressData

type VanityAddressData struct {
	Error string

	Pattern   string
	BountyStr string
	Bounty    float64

	LavishnessStr string
	Lavishness    float64

	ComplexityStr string
	Complexity    float64
}

func init() {

	var err error
	VanityAddressTestTemplate, err = template.ParseFiles("html/VanityAddressTest.html")

	if err != nil {
		return
	}

	DefaultVanityAddressData.Pattern = "1Address"
	DefaultVanityAddressData.Bounty = 1.0

	DefaultVanityAddressData = calculateVanityAddressStuff(DefaultVanityAddressData)
}

func vanityAddressTest(w http.ResponseWriter, r *http.Request) {
	vad := DefaultVanityAddressData

	pattern := r.FormValue("Pattern")
	bounty := r.FormValue("Bounty")

	if pattern != "" && bounty != "" {
		vad.Pattern = pattern
		vad.Bounty = mymath.String2Float(bounty)
		vad = calculateVanityAddressStuff(vad)
	}

	VanityAddressTestTemplate.Execute(w, vad)
}

func calculateVanityAddressStuff(vad VanityAddressData) VanityAddressData {
	answer := vad
	var complexity float64 = 1.0
	var lavishness float64 = 1.0
	var bounty float64 = answer.Bounty

	pattern := answer.Pattern[1:]

	countingOnes := true
	for i := 0; i < len(pattern); i++ {
		if countingOnes {
			if pattern[i] == '1' {
				complexity *= 256
			} else {
				complexity *= 58
				countingOnes = false
			}
		} else {
			complexity *= 58
		}
	}

	lavishness = math.Exp2(32.0) * bounty / complexity

	answer.Complexity = complexity
	answer.Lavishness = lavishness
	answer.ComplexityStr = fmt.Sprintf("%g", complexity)
	answer.LavishnessStr = fmt.Sprintf("%g", lavishness)
	answer.BountyStr = fmt.Sprintf("%.8g", bounty)
	return answer
}
