package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	uuid "github.com/satori/go.uuid"
	jwt "github.com/verxcodes/jwt-go"
)

type Msg struct {
	Url        string    `json:"URL"`
	UUID       uuid.UUID `json:"UUID"`
	ProdCode   string    `json:"product_code"`
	SerNum     string    `json:"serial_number"`
	Batch      string    `json:"batch_number"`
	Expiration string    `json:"expiration_date"`
	OtherInfo  string    `json:"other_info"`
	jwt.StandardClaims
}

func main() {
	const tokenString = `eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJVUkwiOiIiLCJVVUlEIjoiOTBkZmQ2MmMtZjI4My00ZWMwLWI4MjAtZTdiOWM3ZjA3ZTQzIiwicHJvZHVjdF9jb2RlIjoiMDk4NzY1NDMyMTA5ODIiLCJzZXJpYWxfbnVtYmVyIjoiMTIzNDVBWlJRRjEyMzQ1Njc4OTAiLCJiYXRjaF9udW1iZXIiOiJBMUMyRTNHNEk1IiwiZXhwaXJhdGlvbl9kYXRlIjoiMjAxODA3MjEiLCJvdGhlcl9qc29uIjoiJ3t0ZXN0OiIsImp0aSI6IlZlcngiLCJpc3MiOiJ2ZXJ4In0.VwxavGyE1kdZhSdOkfhBCEYMK6f9GJqHyc-irzFlZVCiwJika-fDYn-pky8KF32oWDmLYS8owEebwKipAakf0l0CS6BRmH78TEFTunvjhJt6GIdos54sFldf8psZ_d_C`

	const pubPEM = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEW30TKO1egsJFrrn1u0scTn24sDiflGI2
RC5ehnZhogFWdkJ8Z6eELXLkpzI48KUPenOXwcg7THUK3d3c2Delp9cRtLMXRBbB
ikLNBl15qJu2YuGvJbb0hO7UhhhYu5Db
-----END PUBLIC KEY-----`

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		panic("failed to parse PEM block of the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &Msg{}, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	})

	if claims, ok := token.Claims.(*Msg); ok && token.Valid {
		fmt.Printf("%v %v", claims.Expiration, claims.StandardClaims.ExpiresAt)
		fmt.Println("\nThe token is verified!")
	} else {
		fmt.Println(err)
	}

	fmt.Println("token:", token)
	fmt.Println("err:", err, "\n")

	fmt.Print("Is the token valid? ")

	fmt.Print(token.Valid)
}
