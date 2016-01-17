package app

import (
	"html/template"
	"net/http"
	//"bitelliptic"
	"github.com/ThePiachu/Go/mymath"
	//"fmt"
	//"bitecdsa"
	"log"
)

type VanityAllData struct {
	Error string

	NetByte string
	Prefix  string

	Private1 string
	//private 1 compressed key always has an extra leading 0x01
	Public1Compressed          string
	Public1CompressedAddress   string
	Public1Uncompressed        string
	Public1UncompressedAddress string

	Private2 string
	//private 2 compressed key always has an extra leading 0x01
	Public2Compressed          string
	Public2CompressedAddress   string
	Public2Uncompressed        string
	Public2UncompressedAddress string

	PrivateSumCompressed         string
	PrivateSumUncompressed       string
	PublicSumCompressed          string
	PublicSumCompressedAddress   string
	PublicSumUncompressed        string
	PublicSumUncompressedAddress string
	PrivateSumCompressedWIF      string
	PrivateSumUncompressedWIF    string

	PrivateMultCompressed         string
	PrivateMultUncompressed       string
	PublicMultCompressed          string
	PublicMultCompressedAddress   string
	PublicMultUncompressed        string
	PublicMultUncompressedAddress string
	PrivateMultCompressedWIF      string
	PrivateMultUncompressedWIF    string
}

func (vd *VanityAllData) Calculate() {
	if vd.Private1 != "" {
		vd.Public1Uncompressed = mymath.PrivateKeyToUncompressedPublicKey(vd.Private1)
	}
	if vd.Private2 != "" {
		vd.Public2Uncompressed = mymath.PrivateKeyToUncompressedPublicKey(vd.Private2)
	}

	vd.Public1Compressed = mymath.UncompressedKeyToCompressedKey(vd.Public1Uncompressed)
	vd.Public2Compressed = mymath.UncompressedKeyToCompressedKey(vd.Public2Uncompressed)

	vd.Public1UncompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.Public1Uncompressed)
	vd.Public2UncompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.Public2Uncompressed)

	vd.Public1CompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.Public1Compressed)
	vd.Public2CompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.Public2Compressed)

	if vd.Private1 != "" && vd.Private2 != "" {
		vd.PrivateSumUncompressed = mymath.AddPrivateKeysReturnString(vd.Private1, vd.Private2)
		vd.PrivateMultUncompressed = mymath.MultiplyPrivateKeysReturnString(vd.Private1, vd.Private2)

		vd.PrivateSumCompressed = vd.PrivateSumUncompressed + "01"
		vd.PrivateMultCompressed = vd.PrivateMultUncompressed + "01"

		prefixByte := mymath.Str2Hex(vd.Prefix)[0]

		vd.PrivateSumUncompressedWIF = mymath.PrivateKeyToWIFWithPrefixByte(vd.PrivateSumUncompressed, prefixByte)
		vd.PrivateMultUncompressedWIF = mymath.PrivateKeyToWIFWithPrefixByte(vd.PrivateMultUncompressed, prefixByte)

		vd.PrivateSumCompressedWIF = mymath.PrivateKeyToWIFWithPrefixByte(vd.PrivateSumCompressed, prefixByte)
		vd.PrivateMultCompressedWIF = mymath.PrivateKeyToWIFWithPrefixByte(vd.PrivateMultCompressed, prefixByte)

		vd.PublicSumUncompressed = mymath.PrivateKeyToUncompressedPublicKey(vd.PrivateSumUncompressed)
		vd.PublicMultUncompressed = mymath.PrivateKeyToUncompressedPublicKey(vd.PrivateMultUncompressed)
	} else {
		vd.PrivateSumUncompressed = "??"
		vd.PrivateMultUncompressed = "??"
		vd.PrivateSumUncompressedWIF = "??"
		vd.PrivateMultUncompressedWIF = "??"
		vd.PrivateSumCompressed = "??"
		vd.PrivateMultCompressed = "??"
		vd.PrivateSumCompressedWIF = "??"
		vd.PrivateMultCompressedWIF = "??"

		log.Printf("vd.Public1Uncompressed - %v, vd.Public2Uncompressed - %v", vd.Public1Uncompressed, vd.Public2Uncompressed)
		vd.PublicSumUncompressed = mymath.AddPublicKeysReturnString(vd.Public1Uncompressed, vd.Public2Uncompressed)
		if vd.Private1 != "" {
			vd.PublicMultUncompressed = mymath.MultiplyPrivateAndPublicKeyReturnString(vd.Private1, vd.Public2Uncompressed)
		}
		if vd.Private2 != "" {
			vd.PublicMultUncompressed = mymath.MultiplyPrivateAndPublicKeyReturnString(vd.Private2, vd.Public1Uncompressed)
		}
	}

	vd.PublicSumUncompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.PublicSumUncompressed)
	vd.PublicSumCompressed = mymath.UncompressedKeyToCompressedKey(vd.PublicSumUncompressed)
	vd.PublicSumCompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.PublicSumCompressed)

	if vd.PublicMultUncompressed != "" {
		vd.PublicMultUncompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.PublicMultUncompressed)
		vd.PublicMultCompressed = mymath.UncompressedKeyToCompressedKey(vd.PublicMultUncompressed)
		vd.PublicMultCompressedAddress = mymath.PublicKeyToAddress(vd.NetByte, vd.PublicMultCompressed)
	} else {
		vd.PublicMultUncompressed = "??"
		vd.PublicMultUncompressedAddress = "??"
		vd.PublicMultCompressed = "??"
		vd.PublicMultCompressedAddress = "??"
	}
}

var VanityAllTestTemplate *template.Template //HTML template to use
var DefaultVanityAllData VanityAllData

func init() {
	VanityAllTestTemplate, _ = template.ParseFiles("html/VanityAllTest.html")

	DefaultVanityAllData.NetByte = "0"
	DefaultVanityAllData.Prefix = "80"
	DefaultVanityAllData.Private1 = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
	DefaultVanityAllData.Private2 = "B18427B169E86DE681A1A62588E1D02AE4A7E83C1B413849989A76282A7B562F"

	DefaultVanityAllData.Calculate()
}

func vanityAllTest(w http.ResponseWriter, r *http.Request) {
	vd := VanityAllData{}
	if r.FormValue("Clear") != "" {
		VanityAllTestTemplate.Execute(w, vd)
		return
	}
	if r.FormValue("Random") != "" {
		//set up random data
		vd.NetByte = "0"
		vd.Prefix = "80"
		vd.Private1 = mymath.NewRandomPrivateKey()
		vd.Private2 = mymath.NewRandomPrivateKey()
	}
	if r.FormValue("Calculate") != "" {
		//fetch data from form
		vd.NetByte = mymath.Int642HexString(mymath.HexString2Int64(r.FormValue("NetByte")) % 256)
		vd.Prefix = mymath.Int642HexString(mymath.HexString2Int64(r.FormValue("Prefix")) % 256)
		vd.Private1 = r.FormValue("Private1")
		vd.Private2 = r.FormValue("Private2")

		if vd.Private1 == "" {
			vd.Public1Uncompressed = r.FormValue("Public1Uncompressed")
			vd.Public1Compressed = r.FormValue("Public1Compressed")

			if vd.Public1Uncompressed == "" && vd.Public1Compressed == "" {
				vd.Error = "Input 1 not specified"
				VanityAllTestTemplate.Execute(w, vd)
				return
			}
		} else {
			if mymath.IsPrivateKeyOnCurve(vd.Private1) == false {
				vd.Error = "Private key 1 does not appear to be on the ECDSA curve"
				VanityAllTestTemplate.Execute(w, vd)
				return
			}
		}

		if vd.Private2 == "" {
			vd.Public2Uncompressed = r.FormValue("Public2Uncompressed")
			vd.Public2Compressed = r.FormValue("Public2Compressed")

			if vd.Public2Uncompressed == "" && vd.Public2Compressed == "" {
				vd.Error = "Input 2 not specified"
				VanityAllTestTemplate.Execute(w, vd)
				return
			}
		} else {
			if mymath.IsPrivateKeyOnCurve(vd.Private2) == false {
				vd.Error = "Private key 2 does not appear to be on the ECDSA curve"
				VanityAllTestTemplate.Execute(w, vd)
				return
			}
		}
	}
	if r.FormValue("Calculate") != "" || r.FormValue("Random") != "" {
		vd.Calculate()
		VanityAllTestTemplate.Execute(w, vd)
	} else {
		VanityAllTestTemplate.Execute(w, DefaultVanityAllData)
	}

}
