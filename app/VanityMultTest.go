package app

import (
	"crypto/rand"
	"github.com/ThePiachu/Go/mymath"
	"github.com/ThePiachu/Go/mymath/bitecdsa"
	"github.com/ThePiachu/Go/mymath/bitelliptic"
	"html/template"
	"log"
	"net/http"
)

type VanityMultData struct {
	Error string

	Private1 string //Private key kept secure
	Public1  string //Public key used for generation

	Private2 string
	Public2  string

	PrivateMult       string
	PrivateMultPublic string

	Public2Address     string
	PrivateMultAddress string
}

var VanityMultTestTemplate *template.Template //HTML template to use
var DefaultVanityMultData VanityMultData

func init() {

	var err error
	VanityMultTestTemplate, err = template.ParseFiles("html/VanityMultTest.html")

	if err != nil {
		log.Print("init err ", err)
		return
	}

	DefaultVanityMultData.Private1 = "8D358EDA964A16786CF4089268881C52370FCB34426F56602BE0DE39FBE49E49"
	DefaultVanityMultData.Public1 = "04E93A33A16816FA073B03849B03954F13E0911BC089045F6554F7D6A0EB90EB1261EB52FE1BC189943C7A0C0032805B4330A597C79FFB974AA5604A7809D9D0D6"

	DefaultVanityMultData.Private2 = "1B4019E609EB8EBDA9F7260B305D456831FC706B942268C2D4017BBA92953414"
	DefaultVanityMultData.Public2 = "04FE7AA94E7131DAB9C3B2FD8A4637457A0BF5FC182BD8C00EB0C3BDCC0223F6C5AD1E82EF3575DD2415E0623A413DB894207A03D727E432B8F7FBB1F71583042C"

	DefaultVanityMultData.PrivateMult = "61277795A6305233004CE43532AEEB30516D400D9C0D8B5BFBDE2D260D675C32"
	DefaultVanityMultData.PrivateMultPublic = "04FE7AA94E7131DAB9C3B2FD8A4637457A0BF5FC182BD8C00EB0C3BDCC0223F6C5AD1E82EF3575DD2415E0623A413DB894207A03D727E432B8F7FBB1F71583042C"

	DefaultVanityMultData.Public2Address = "1FyN7e8Svo6iPFteXiy439mwzUj9tNWeZF"
	DefaultVanityMultData.PrivateMultAddress = "1FyN7e8Svo6iPFteXiy439mwzUj9tNWeZF"

}

func vanityMultTest(w http.ResponseWriter, r *http.Request) {
	curve := bitelliptic.S256()

	if r.FormValue("Random") != "" {
		vd := new(VanityMultData)

		priv, gx, gy, _ := curve.GenerateKey(rand.Reader)
		vd.Private1 = mymath.Hex2Str(priv)
		one, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private1))
		vd.Public1 = mymath.Hex2Str(one.PublicKey)

		curve2 := curve.Copy()
		curve2.Gx = gx
		curve2.Gy = gy
		priv, _, _, _ = curve2.GenerateKey(rand.Reader)
		vd.Private2 = mymath.Hex2Str(priv)

		two, _ := mymath.NewAddressFromPrivateKeyWithCurve(mymath.Str2Hex(vd.Private2), curve2)

		vd.Public2 = mymath.Hex2Str(two.PublicKey)

		vd.Public2Address = string(two.Base)

		vd.PrivateMult = mymath.Hex2Str(mymath.Big2Hex(mymath.MultiplyPrivateKeys(vd.Private1, vd.Private2)))

		zero, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.PrivateMult))
		vd.PrivateMultPublic = mymath.Hex2Str(zero.PublicKey)
		vd.PrivateMultAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PrivateMultPublic)).Base)

		VanityMultTestTemplate.Execute(w, vd)
		return
	} else if r.FormValue("Private") != "" {
		vd := new(VanityMultData)

		if bitecdsa.CheckIsOnCurve(curve, mymath.Str2Big(r.FormValue("Private1"))) != true {
			vd.Error = "Private key 1 is invalid"
		} else {
			priv1, _ := bitecdsa.GenerateFromPrivateKey(mymath.Str2Big(r.FormValue("Private1")), curve)

			vd.Private1 = mymath.Hex2Str(mymath.Big2Hex(priv1.D))
			one, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.Private1))
			vd.Public1 = mymath.Hex2Str(one.PublicKey)

			curve2 := curve.Copy()
			curve2.Gx = priv1.PublicKey.X
			curve2.Gy = priv1.PublicKey.Y
			if bitecdsa.CheckIsOnCurve(curve2, mymath.Str2Big(r.FormValue("Private2"))) != true {
				vd.Error = "Private key 2 is invalid"
			} else {
				priv2, _ := bitecdsa.GenerateFromPrivateKey(mymath.Str2Big(r.FormValue("Private2")), curve2)
				vd.Private2 = mymath.Hex2Str(mymath.Big2Hex(priv2.D))

				two, _ := mymath.NewAddressFromPrivateKeyWithCurve(mymath.Str2Hex(vd.Private2), curve2)

				vd.Public2 = mymath.Hex2Str(two.PublicKey)

				vd.Public2Address = string(two.Base)

				vd.PrivateMult = mymath.Hex2Str(mymath.Big2Hex(mymath.MultiplyPrivateKeys(vd.Private1, vd.Private2)))

				zero, _ := mymath.NewAddressFromPrivateKey(mymath.Str2Hex(vd.PrivateMult))
				vd.PrivateMultPublic = mymath.Hex2Str(zero.PublicKey)
				vd.PrivateMultAddress = string(mymath.NewFromPublicKey(0x00, mymath.Str2Hex(vd.PrivateMultPublic)).Base)
			}
		}
		VanityMultTestTemplate.Execute(w, vd)

		return
	} else if r.FormValue("Public") != "" {
		vd := new(VanityMultData)

		vd.Public1 = r.FormValue("Public1")
		if len(vd.Public1) != 130 {
			vd.Error = "Public key is invalid"
		} else if vd.Public1[0] != '0' || vd.Public1[1] != '4' {
			vd.Error = "Public key is invalid"
		} else {
			gx, gy := mymath.PublicKeyToPointCoordinates(vd.Public1)

			curve2 := curve.Copy()
			curve2.Gx = gx
			curve2.Gy = gy
			vd.Private1 = ""

			if bitecdsa.CheckIsOnCurve(curve2, mymath.Str2Big(r.FormValue("Private2"))) != true {
				vd.Error = "Private key is invalid"
			} else {

				priv2, _ := bitecdsa.GenerateFromPrivateKey(mymath.Str2Big(r.FormValue("Private2")), curve2)
				vd.Private2 = mymath.Hex2Str(mymath.Big2Hex(priv2.D))

				two, _ := mymath.NewAddressFromPrivateKeyWithCurve(mymath.Str2Hex(vd.Private2), curve2)

				vd.Public2 = mymath.Hex2Str(two.PublicKey)

				vd.Public2Address = string(two.Base)

				vd.PrivateMult = "??"

				vd.PrivateMultPublic = "??"
				vd.PrivateMultAddress = "??"
			}
		}
		VanityMultTestTemplate.Execute(w, vd)

		return
	} else {
		VanityMultTestTemplate.Execute(w, DefaultVanityMultData)
	}

}
