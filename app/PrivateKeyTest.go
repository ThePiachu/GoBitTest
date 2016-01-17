package app

import (
	"crypto/rand"
	"github.com/ThePiachu/Go/mymath"
	"github.com/ThePiachu/Go/mymath/bitecdsa"
	"github.com/ThePiachu/Go/mymath/bitelliptic"
	"html/template"
	"net/http"
)

type PrivateKeyDat struct {
	Error string

	Priv2WIF []string

	WIF2Priv []string

	WIFChecksum []string

	UseMinikey bool

	Minikey []string
}

var PrivateKeyTestTemplate *template.Template //HTML template to use
var DefaultPrivKeyDat PrivateKeyDat

func init() {

	var err error
	PrivateKeyTestTemplate, err = template.ParseFiles("html/PrivateKeyTest.html")

	if err != nil {
		return
	}

	DefaultPrivKeyDat.WIF2Priv = []string{"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
		"0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"}

	DefaultPrivKeyDat.Priv2WIF = []string{"0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
		"8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592",
		"507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714",
		"507A5B8D",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D",
		"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"}

	DefaultPrivKeyDat.WIFChecksum = []string{"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D",
		"800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D",
		"8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592",
		"507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714",
		"507A5B8D",
		"507A5B8D"}
	DefaultPrivKeyDat.Minikey = []string{"", "", "", "", "", "", "", ""}
	DefaultPrivKeyDat.UseMinikey = false
}

func privateKeyTest(w http.ResponseWriter, r *http.Request) {

	if r.FormValue("Random") != "" {
		curve := bitelliptic.S256()
		priv, _, _, _ := curve.GenerateKey(rand.Reader)
		copyPriv := generateFromPrivate(DefaultPrivKeyDat, mymath.Hex2Str(priv))
		copyPriv = generateFromWIF(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		copyPriv = generateFromChecksum(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		PrivateKeyTestTemplate.Execute(w, copyPriv)
	} else if r.FormValue("wif") != "" {
		copyPriv := generateFromWIF(DefaultPrivKeyDat, r.FormValue("wif"))
		copyPriv = generateFromPrivate(copyPriv, copyPriv.WIF2Priv[len(copyPriv.WIF2Priv)-1])
		copyPriv = generateFromChecksum(copyPriv, r.FormValue("wif"))
		PrivateKeyTestTemplate.Execute(w, copyPriv)
	} else if r.FormValue("wif2") != "" {
		copyPriv := generateFromWIF(DefaultPrivKeyDat, r.FormValue("wif2"))
		copyPriv = generateFromPrivate(copyPriv, copyPriv.WIF2Priv[len(copyPriv.WIF2Priv)-1])
		copyPriv = generateFromChecksum(copyPriv, r.FormValue("wif2"))
		PrivateKeyTestTemplate.Execute(w, copyPriv)
	} else if r.FormValue("wif3") != "" {
		copyPriv := generateFromWIF(DefaultPrivKeyDat, r.FormValue("wif3"))
		copyPriv = generateFromPrivate(copyPriv, copyPriv.WIF2Priv[len(copyPriv.WIF2Priv)-1])
		copyPriv = generateFromChecksum(copyPriv, r.FormValue("wif3"))
		PrivateKeyTestTemplate.Execute(w, copyPriv)
	} else if r.FormValue("private") != "" {
		copyPriv := generateFromPrivate(DefaultPrivKeyDat, r.FormValue("private"))
		copyPriv = generateFromWIF(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		copyPriv = generateFromChecksum(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		PrivateKeyTestTemplate.Execute(w, copyPriv)

	} else if r.FormValue("private2") != "" {
		copyPriv := generateFromPrivate(DefaultPrivKeyDat, r.FormValue("private2"))
		copyPriv = generateFromWIF(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		copyPriv = generateFromChecksum(copyPriv, copyPriv.Priv2WIF[len(copyPriv.Priv2WIF)-1])
		PrivateKeyTestTemplate.Execute(w, copyPriv)

	} else {
		PrivateKeyTestTemplate.Execute(w, DefaultPrivKeyDat)
	}

}

func generateFromWIF(in PrivateKeyDat, WIF string) PrivateKeyDat {
	var answer PrivateKeyDat
	answer.Error = in.Error

	answer.Priv2WIF = in.Priv2WIF
	answer.WIF2Priv = []string{}
	answer.WIFChecksum = in.WIFChecksum
	answer.Minikey = in.Minikey

	hex := mymath.Base582Hex(WIF)
	if mymath.Hex2Base58(hex) != mymath.Base58(WIF) {
		if answer.Error == "" {
			answer.Error = "Invalid Base58 encoding"
		}
		answer.WIF2Priv = []string{WIF, "", "", ""}
		return answer
	}
	answer.WIF2Priv = append(answer.WIF2Priv, WIF)
	answer.WIF2Priv = append(answer.WIF2Priv, mymath.Hex2Str(hex))
	answer.WIF2Priv = append(answer.WIF2Priv, mymath.Hex2Str(hex[0:len(hex)-4]))
	answer.WIF2Priv = append(answer.WIF2Priv, mymath.Hex2Str(hex[1:len(hex)-4]))

	return answer
}

func generateFromPrivate(in PrivateKeyDat, Private string) PrivateKeyDat {
	var answer PrivateKeyDat
	answer.Error = in.Error

	answer.Priv2WIF = []string{}
	answer.WIF2Priv = in.WIF2Priv
	answer.WIFChecksum = in.WIFChecksum
	answer.Minikey = in.Minikey

	curve := bitelliptic.S256()
	if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(Private)) == false {
		if answer.Error == "" {
			answer.Error = "Private key is not on curve"
		}
		answer.Priv2WIF = []string{Private, "", "", "", "", "", ""}
		return answer
	}
	priv := append([]byte{0x80}, mymath.Str2Hex(Private)...)
	answer.Priv2WIF = append(answer.Priv2WIF, Private)
	answer.Priv2WIF = append(answer.Priv2WIF, mymath.Hex2Str(priv))
	sha := mymath.SingleSHA(priv)
	answer.Priv2WIF = append(answer.Priv2WIF, mymath.Hex2Str(sha))
	sha = mymath.SingleSHA(sha)
	answer.Priv2WIF = append(answer.Priv2WIF, mymath.Hex2Str(sha))
	answer.Priv2WIF = append(answer.Priv2WIF, mymath.Hex2Str(sha[0:4]))
	priv = append(priv, sha[0:4]...)
	answer.Priv2WIF = append(answer.Priv2WIF, mymath.Hex2Str(priv))
	answer.Priv2WIF = append(answer.Priv2WIF, string(mymath.Hex2Base58(priv)))

	return answer
}
func generateFromChecksum(in PrivateKeyDat, WIF string) PrivateKeyDat {
	var answer PrivateKeyDat
	answer.Error = in.Error

	answer.Priv2WIF = in.Priv2WIF
	answer.WIF2Priv = in.WIF2Priv
	answer.WIFChecksum = []string{}
	answer.Minikey = in.Minikey

	hex := mymath.Base582Hex(WIF)
	if mymath.Hex2Base58(hex) != mymath.Base58(WIF) {
		if answer.Error == "" {
			answer.Error = "Invalid Base58 encoding"
		}
		answer.WIFChecksum = []string{WIF, "", "", "", "", "", ""}
		return answer
	}
	answer.WIFChecksum = append(answer.WIFChecksum, WIF)
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(hex))
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(hex[0:len(hex)-4]))
	sha := mymath.SingleSHA(hex[0 : len(hex)-4])
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(sha))
	sha = mymath.SingleSHA(sha)
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(sha))
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(sha[0:4]))
	answer.WIFChecksum = append(answer.WIFChecksum, mymath.Hex2Str(hex[len(hex)-4:]))

	return answer
}
