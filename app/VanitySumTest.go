package main

import (
	"crypto/rand"
	"fmt"
	"github.com/ThePiachu/Go/mymath"
	"github.com/ThePiachu/Go/mymath/bitecdsa"
	"github.com/ThePiachu/Go/mymath/bitelliptic"
	"html/template"
	"net/http"
)

type VanitySumData struct {
	Error string

	Private1 string
	Private2 string

	PrivateSum        string
	PrivateSumPublic  string
	PrivateSumAddress string

	Public1 string
	Public2 string

	PublicSum     string
	PublicAddress string
}

var VanitySumTestTemplate *template.Template //HTML template to use
var DefaultVanitySumData VanitySumData

func init() {

	var err error
	VanitySumTestTemplate, err = template.ParseFiles("html/VanitySumTest.html")

	if err != nil {
		return
	}

	DefaultVanitySumData.Private1 = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
	DefaultVanitySumData.Private2 = "B18427B169E86DE681A1A62588E1D02AE4A7E83C1B413849989A76282A7B562F"

	DefaultVanitySumData.PrivateSum = "CA65722CD418ED28EC369E36CFE3B7F3CC1CD035BFBF6469CE759FCA30AD6D54"
	DefaultVanitySumData.PrivateSumPublic = "0436970CE32E14DC06AC50217CDCF53E628B32810707080D6848D9C8D4BE9FE461E100E705CCA9854436A1283210CCEFBB6B16CB9A86B009488922A8F302A27487"
	DefaultVanitySumData.PrivateSumAddress = "166ev9JXn2rFqiPSQAwM7qJYpNL1JrNf3h"

	DefaultVanitySumData.Public1 = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
	DefaultVanitySumData.Public2 = "049C95E0949E397FACCECF0FE8EAD247E6FD082717E4A4A876049FB34A9ADED110DFEA2EF691CC4A1410498F4C312F3A94318CD5B6F0E8E92051064876751C8404"

	DefaultVanitySumData.PublicSum = "0436970CE32E14DC06AC50217CDCF53E628B32810707080D6848D9C8D4BE9FE461E100E705CCA9854436A1283210CCEFBB6B16CB9A86B009488922A8F302A27487"
	DefaultVanitySumData.PublicAddress = "166ev9JXn2rFqiPSQAwM7qJYpNL1JrNf3h"
}

func vanitySumTest(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("Random") != "" {
		vd := new(VanitySumData)

		curve := bitelliptic.S256()
		priv, _, _, _ := curve.GenerateKey(rand.Reader)
		vd.Private1 = mymath.Hex2Str(priv)
		priv, _, _, _ = curve.GenerateKey(rand.Reader)
		vd.Private2 = mymath.Hex2Str(priv)

		vd.PrivateSum = mymath.Hex2Str(mymath.Big2Hex(mymath.AddPrivateKeys(vd.Private1, vd.Private2)))

		zero, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.PrivateSum))
		vd.PrivateSumPublic = mymath.Hex2Str(zero.PublicKey)
		vd.PrivateSumAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PrivateSumPublic)).Base)

		one, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private1))
		two, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private2))
		vd.Public1 = mymath.Hex2Str(one.PublicKey)
		vd.Public2 = mymath.Hex2Str(two.PublicKey)

		a, b := mymath.AddPublicKeys(vd.Public1, vd.Public2)
		vd.PublicSum = "04" + mymath.Hex2Str(mymath.Big2HexPadded(a, 32)) + mymath.Hex2Str(mymath.Big2HexPadded(b, 32))
		vd.PublicAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PublicSum)).Base)

		VanitySumTestTemplate.Execute(w, vd)
	} else if r.FormValue("Private") != "" {
		vd := new(VanitySumData)
		vd.Private1 = r.FormValue("Private1")
		vd.Private2 = r.FormValue("Private2")

		curve := bitelliptic.S256()
		if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private1)) == false || bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private2)) == false {
			if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private1)) == false && bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private2)) == false {
				vd.Error = "Both private keys appear to be invalid"

			} else if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private1)) == false {
				vd.Error = fmt.Sprintf("Private key one (%s) appears to be invalid", vd.Private1)

			} else if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(vd.Private2)) == false {
				vd.Error = fmt.Sprintf("Private key two (%s) appears to be invalid", vd.Private2)

			} else {
				vd.Error = "One of the private keys is invalid, but we can't figure out which (this is an unexpected server behaviour)."
			}
		} else {
			vd.PrivateSum = mymath.Hex2Str(mymath.Big2Hex(mymath.AddPrivateKeys(vd.Private1, vd.Private2)))

			zero, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.PrivateSum))
			vd.PrivateSumPublic = mymath.Hex2Str(zero.PublicKey)
			vd.PrivateSumAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PrivateSumPublic)).Base)

			one, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private1))
			two, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private2))
			vd.Public1 = mymath.Hex2Str(one.PublicKey)
			vd.Public2 = mymath.Hex2Str(two.PublicKey)

			a, b := mymath.AddPublicKeys(vd.Public1, vd.Public2)
			vd.PublicSum = "04" + mymath.Hex2Str(mymath.Big2HexPadded(a, 32)) + mymath.Hex2Str(mymath.Big2HexPadded(b, 32))
			vd.PublicAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PublicSum)).Base)
		}

		VanitySumTestTemplate.Execute(w, vd)

	} else if r.FormValue("Public") != "" {
		vd := new(VanitySumData)
		vd.Public1 = r.FormValue("Public1")
		vd.Public2 = r.FormValue("Public2")

		if len(vd.Public1) != 130 || len(vd.Public2) != 130 {
			vd.Error = "Public keys are invalid"
		} else if vd.Public1[0] != '0' || vd.Public1[1] != '4' || vd.Public2[0] != '0' || vd.Public2[1] != '4' {
			vd.Error = "Public keys are invalid"
		} else {
			a, b := mymath.AddPublicKeys(vd.Public1, vd.Public2)
			vd.PublicSum = "04" + mymath.Hex2Str(mymath.Big2HexPadded(a, 32)) + mymath.Hex2Str(mymath.Big2HexPadded(b, 32))
			vd.PublicAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PublicSum)).Base)
		}

		VanitySumTestTemplate.Execute(w, vd)
	} else {
		VanitySumTestTemplate.Execute(w, DefaultVanitySumData)
	}

}
