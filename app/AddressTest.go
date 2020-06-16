package main

import (
	"crypto/rand"
	"html/template"
	"net/http"

	"google.golang.org/appengine"

	"github.com/ThePiachu/Go/Log"
	"github.com/ThePiachu/Go/mymath"
	"github.com/ThePiachu/Go/mymath/bitecdsa"
	"github.com/ThePiachu/Go/mymath/bitelliptic"
)

type AddressDat struct {
	Error string

	HashString []string
}

var AddressTestTemplate *template.Template //HTML template to use
var DefaultAddress AddressDat

func init() {

	var err error
	AddressTestTemplate, err = template.ParseFiles("html/AddressTest.html")

	if err != nil {
		return
	}

	DefaultAddress.HashString = []string{
		"18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725",
		"0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6",
		"600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408",
		"010966776006953D5567439E5E39F86A0D273BEE",
		"00010966776006953D5567439E5E39F86A0D273BEE",
		"445C7A8007A93D8733188288BB320A8FE2DEBD2AE1B47F0F50BC10BAE845C094",
		"D61967F63C7DD183914A4AE452C9F6AD5D462CE3D277798075B107615C1A8A30",
		"D61967F6",
		"00010966776006953D5567439E5E39F86A0D273BEED61967F6",
		"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"}

}

func addressTest(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	if r.FormValue("Random") != "" {
		var address AddressDat
		curve := bitelliptic.S256()
		priv, x, y, _ := curve.GenerateKey(rand.Reader)
		pub := append(append([]byte{0x04}, mymath.Big2HexWithMinimumLength(x, 32)...), mymath.Big2HexWithMinimumLength(y, 32)...)
		//pub=mymath.Str2Hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")

		st2 := mymath.SingleSHA(pub)
		st3 := mymath.Ripemd(st2)
		st4 := append([]byte{0x00}, st3[:]...)
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		st8 := append(st4[:], st7[:]...)
		st9 := mymath.Hex2Base58(st8)

		address.HashString = []string{
			mymath.Hex2Str(priv),
			mymath.Hex2Str(pub),
			mymath.Hex2Str(st2),
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)

	} else if r.FormValue("private") != "" {
		var err error
		var address AddressDat
		curve := bitelliptic.S256()
		privs, err := bitecdsa.GenerateFromPrivateKey(mymath.Str2Big(r.FormValue("private")), curve)
		if err != nil {
			if err.Error() == "Private key is not on curve" {
				address = DefaultAddress
				address.Error = "Private key is not on curve"
				AddressTestTemplate.Execute(w, address)
			} else {
				Log.Errorf(c, "Err ", err)
				return
			}
		} else {
			priv := mymath.Big2Hex(privs.D)
			x := privs.PublicKey.X
			y := privs.PublicKey.Y
			//priv, x, y, _:=curve.GenerateKey(rand.Reader)
			pub := append(append([]byte{0x04}, mymath.Big2HexWithMinimumLength(x, 32)...), mymath.Big2HexWithMinimumLength(y, 32)...)

			st2 := mymath.SingleSHA(pub)
			st3 := mymath.Ripemd(st2)
			st4 := append([]byte{0x00}, st3[:]...)
			st5 := mymath.SingleSHA(st4)
			st6 := mymath.SingleSHA(st5)
			st7 := st6[0:4]
			st8 := append(st4[:], st7[:]...)
			st9 := mymath.Hex2Base58(st8)

			address.HashString = []string{
				mymath.Hex2Str(priv),
				mymath.Hex2Str(pub),
				mymath.Hex2Str(st2),
				mymath.Hex2Str(st3),
				mymath.Hex2Str(st4),
				mymath.Hex2Str(st5),
				mymath.Hex2Str(st6),
				mymath.Hex2Str(st7),
				mymath.Hex2Str(st8),
				string(st9)}
			AddressTestTemplate.Execute(w, address)
		}

	} else if r.FormValue("public") != "" {
		var address AddressDat

		pub := mymath.Str2Hex(r.FormValue("public"))
		if len(pub) != 65 {
			address.Error = "Invalid public key length"
		} else if pub[0] != 0x04 {
			address.Error = "Invalid public key format"
		}

		st2 := mymath.SingleSHA(pub)
		st3 := mymath.Ripemd(st2)
		st4 := append([]byte{0x00}, st3[:]...)
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		st8 := append(st4[:], st7[:]...)
		st9 := mymath.Hex2Base58(st8)

		address.HashString = []string{
			"",
			mymath.Hex2Str(pub),
			mymath.Hex2Str(st2),
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)
	} else if r.FormValue("RIPEMD") != "" {
		var address AddressDat

		st3 := mymath.Str2Hex(r.FormValue("RIPEMD"))
		if len(st3) != 20 {
			address.Error = "Invalid RIPEMD-160 length"
		}

		st4 := append([]byte{0x00}, st3[:]...)
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		st8 := append(st4[:], st7[:]...)
		st9 := mymath.Hex2Base58(st8)

		address.HashString = []string{
			"", "", "",
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)
	} else if r.FormValue("RIPEMDWithHash") != "" {
		var address AddressDat

		st4 := mymath.Str2Hex(r.FormValue("RIPEMDWithHash"))
		if len(st4) != 21 {
			address.Error = "Invalid RIPEMD-160 length"
		}
		st3 := st4[1:]
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		st8 := append(st4[:], st7[:]...)
		st9 := mymath.Hex2Base58(st8)

		address.HashString = []string{
			"", "", "",
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)
	} else if r.FormValue("FullAddress") != "" {
		var address AddressDat

		st8 := mymath.Str2Hex(r.FormValue("FullAddress"))
		if len(st8) != 25 {
			address.Error = "Invalid address length"
			Log.Debugf(c, "%d", len(st8))
		}

		st3 := st8[1:21]
		st4 := append([]byte{0x00}, st3[:]...)
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		//st8:=append(st4[:], st7[:]...)
		st9 := mymath.Hex2Base58(st8)
		if len(st8) == 25 {
			if st7[3] != st8[24] || st7[2] != st8[23] || st7[1] != st8[22] || st7[0] != st8[21] {
				address.Error = "Invalid checksum"
			}
		}

		address.HashString = []string{
			"", "", "",
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)
	} else if r.FormValue("Base58") != "" {
		var address AddressDat

		st9 := r.FormValue("Base58")
		st8 := mymath.Base582Hex(st9)
		if len(st8) != 25 {
			address.Error = "Invalid address length"
			Log.Debugf(c, "%d", len(st8))
		}

		st3 := st8[1:21]
		st4 := append([]byte{0x00}, st3[:]...)
		st5 := mymath.SingleSHA(st4)
		st6 := mymath.SingleSHA(st5)
		st7 := st6[0:4]
		//st8:=append(st4[:], st7[:]...)
		//st9:=mymath.Hex2Base58(st8)
		if len(st8) == 25 {
			if st7[3] != st8[24] || st7[2] != st8[23] || st7[1] != st8[22] || st7[0] != st8[21] {
				address.Error = "Invalid checksum"
			}
		}

		address.HashString = []string{
			"", "", "",
			mymath.Hex2Str(st3),
			mymath.Hex2Str(st4),
			mymath.Hex2Str(st5),
			mymath.Hex2Str(st6),
			mymath.Hex2Str(st7),
			mymath.Hex2Str(st8),
			string(st9)}
		AddressTestTemplate.Execute(w, address)
	} else {
		AddressTestTemplate.Execute(w, DefaultAddress)
	}

}
