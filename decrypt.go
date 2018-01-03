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
	ProdCode   string    `json:"prd"`
	SerNum     string    `json:"ser"`
	Batch      string    `json:"batch"`
	Expiration string    `json:"expires"` // StandardClaims already have exp for ExpiresAt
	OtherInfo  string    `json:"other"`
	jwt.StandardClaims
}

func main() {
	const tokenString = `eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJVUkwiOiJodHRwczovL3ZlcnguY29kZXMvcHVibGljX2tleS5wZW0iLCJVVUlEIjoiMzQ3ZmMwZmMtZGMxNy00YWEyLWI3MjAtNWY4YjY0Y2Q2ZjVjIiwicHJkIjoiMDk4NzY1NDMyMTA5ODIiLCJzZXIiOiIxMjM0NUFaUlFGMTIzNDU2Nzg5MCIsImJhdGNoIjoiQTFDMkUzRzRJNSIsImV4cGlyZXMiOiIyMDE4MDcyMSIsIm90aGVyIjoie1widGVzdFwiOiB0cnVlfSIsImp0aSI6IlZlcngiLCJpc3MiOiJ2ZXJ4In0.FNSjzuriFU3xeAdVkYYCw3or_ZZ8QwYZPLCVkOjRw2zppF7LcYJL6KY2mze3lMOzEVwbaC3D8LECC25KrmVae3MgohmuMV9Wrh0Q9hgG0R0-iRrNola2Azb2d6r7zNhm`

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
