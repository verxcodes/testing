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
	const tokenString = `eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJVUkwiOiJodHRwczovL3ZlcnguY29kZXMvcHVibGljX2tleS5wZW0iLCJVVUlEIjoiNmI5YzE1OTMtYmRmYy00NWY0LTgzOGYtMjJhODYzNWZlYWY3IiwicHJvZHVjdF9jb2RlIjoiMDk4NzY1NDMyMTA5ODIiLCJzZXJpYWxfbnVtYmVyIjoiMTIzNDVBWlJRRjEyMzQ1Njc4OTAiLCJiYXRjaF9udW1iZXIiOiJBMUMyRTNHNEk1IiwiZXhwaXJhdGlvbl9kYXRlIjoiMjAxODA3MjEiLCJvdGhlcl9pbmZvIjoiJ3t0ZXN0OiIsImp0aSI6IlZlcngiLCJpc3MiOiJ2ZXJ4In0.tQopyHHw0QpSBJOUg2mPlTt3IVV4QIim38G7wA4gFYQmtbF--svGHN8LKh8jM1Oc5yY3G_JmPEoat4BT453urRwcFZoBdkel8HY6YyAhEKusm5AfI9Kahix7C8KUiqx9`

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

	fmt.Println("\nIs the JWT token valid? ", token.Valid)

	fmt.Println("\nCustom Claims:")

	claims, ok := token.Claims.(*Msg)
	if !ok {
		fmt.Println("Error getting JWT claims!")
	}

	fmt.Println("\tUrl:", claims.Url)
	fmt.Println("\tUUID:", claims.UUID)
	fmt.Println("\tProdCode:", claims.ProdCode)
	fmt.Println("\tSerNum:", claims.SerNum)
	fmt.Println("\tBatch:", claims.Batch)
	fmt.Println("\tExpiration:", claims.Expiration)
	fmt.Println("\tOtherInfo:", claims.OtherInfo, "\n")

	fmt.Println("Standard Claims:")
	fmt.Println("\tAudience:", claims.Audience)
	fmt.Println("\tExpiresAt:", claims.ExpiresAt)
	fmt.Println("\tId:", claims.Id)
	fmt.Println("\tIssuedAt:", claims.IssuedAt)
	fmt.Println("\tIssuer:", claims.Issuer)
	fmt.Println("\tNotBefore:", claims.NotBefore)
	fmt.Println("\tSubject:", claims.Subject, "\n")

	fmt.Println("err:", err, "\n")
}
