package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

var (
	p, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	n, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	Gx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	Gy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
)

type Point struct {
	x, y *big.Int
}

func (p Point) String() string {
	return fmt.Sprintf("{'x': %s, 'y': %s}", p.x.String(), p.y.String())
}

var G = Point{Gx, Gy}

func taggedHash(tag string, message []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(message)
	return h.Sum(nil)
}

func assertNotInfinity(p *Point) {
	if p == nil {
		panic("Point is at infinity")
	}
}

func x(p *Point) *big.Int {
	assertNotInfinity(p)
	return p.x
}

func y(p *Point) *big.Int {
	assertNotInfinity(p)
	return p.y
}

func add(p1, p2 *Point) *Point {
	if p1 == nil {
		return p2
	} else if p2 == nil {
		return p1
	}
	var lambda big.Int
	if p1 == p2 {
		// lambda = 3 * x(p1) * x(p1) * exp(2 * y(p1), p - 2, p)
		lambda.Mul(
			new(big.Int).Mul(
				big.NewInt(3),
				new(big.Int).Mul(x(p1), x(p1)),
			),
			new(big.Int).Exp(
				new(big.Int).Mul(big.NewInt(2), y(p1)),
				new(big.Int).Sub(p, big.NewInt(2)),
				p,
			),
		)
	} else {
		// lambda = (y(p2) - y(p1)) * exp(x(p2) - x(p1), p - 2, p)
		lambda.Mul(
			new(big.Int).Sub(y(p2), y(p1)),
			new(big.Int).Exp(
				new(big.Int).Sub(x(p2), x(p1)),
				new(big.Int).Sub(p, big.NewInt(2)),
				p,
			),
		)
	}
	// modulo p
	lambda.Mod(&lambda, p)

	// x3 = lambda * lambda - x1 - x2
	x3 := new(big.Int).Mul(&lambda, &lambda)
	x3.Sub(x3, x(p1))
	x3.Sub(x3, x(p2))
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1
	y3 := new(big.Int).Mul(&lambda, new(big.Int).Sub(x(p1), x3))
	y3.Sub(y3, y(p1))
	y3.Mod(y3, p)

	return &Point{x3, y3}
}

func mul(p1 *Point, n1 *big.Int) *Point {
	var r *Point
	for i := range 256 {
		if new(big.Int).And(
			new(big.Int).Rsh(n1, uint(i)),
			big.NewInt(1),
		).Cmp(big.NewInt(1)) == 0 {
			r = add(r, p1)
		}
		p1 = add(p1, p1)
	}
	assertNotInfinity(r)
	return r
}

func bytesFromInt(i *big.Int) []byte {
	b := i.Bytes()
	// pad out to 32 bytes
	if len(b) < 32 {
		b = append(bytes.Repeat([]byte{0}, 32-len(b)), b...)
	}
	return b
}

func bytesFromPoint(p Point) []byte {
	return bytesFromInt(x(&p))
}

func xorBytes(b1, b2 []byte) []byte {
	b := make([]byte, len(b1))
	for i := range b1 {
		b[i] = b1[i] ^ b2[i]
	}
	return b
}

func liftX(x *big.Int) *Point {
	if x.Cmp(p) >= 0 {
		return nil
	}
	ySq := new(big.Int).Exp(x, big.NewInt(3), p)
	ySq.Add(ySq, big.NewInt(7))
	ySq.Mod(ySq, p)
	y := new(big.Int).Exp(
		ySq,
		new(big.Int).Div(new(big.Int).Add(p, big.NewInt(1)),
			big.NewInt(4)),
		p,
	)

	if new(big.Int).Exp(y, big.NewInt(2), p).Cmp(ySq) != 0 {
		return nil
	}

	if new(big.Int).And(y, big.NewInt(1)).Cmp(big.NewInt(0)) == 0 {
		return &Point{x, y}
	} else {
		return &Point{x, new(big.Int).Sub(p, y)}
	}
}

func intFromBytes(b []byte) *big.Int {
	result := new(big.Int)
	for _, v := range b {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(v)))
	}
	return result
}

func hasEvenY(p *Point) bool {
	assertNotInfinity(p)
	return new(big.Int).Mod(y(p), big.NewInt(2)).Cmp(big.NewInt(0)) == 0
}

func pubkeyGen(seckey []byte) []byte {
	d0 := intFromBytes(seckey)
	// if d0 < 1 or d0 > n - 1
	if d0.Cmp(big.NewInt(1)) < 0 || d0.Cmp(new(big.Int).Sub(n, big.NewInt(1))) > 0 {
		panic("The secret key must be an integer in the range 1..n-1.")
	}
	P := mul(&G, d0)
	assertNotInfinity(P)
	return bytesFromPoint(*P)
}

func schnorrSign(message, seckey, auxRand []byte) []byte {
	d0 := intFromBytes(seckey)
	// if d0 < 1 or d0 > n - 1
	if d0.Cmp(big.NewInt(1)) < 0 || d0.Cmp(new(big.Int).Sub(n, big.NewInt(1))) > 0 {
		panic("The secret key must be an integer in the range 1..n-1.")
	} else if len(auxRand) != 32 {
		panic("auxRand must be 32 bytes")
	}
	P := mul(&G, d0)
	assertNotInfinity(P)
	var d *big.Int
	if hasEvenY(P) {
		d = d0
	} else {
		d = new(big.Int).Sub(n, d0)
	}
	t := xorBytes(bytesFromInt(d), taggedHash("BIP0340/aux", auxRand))
	// hashTag = t + bytesFromPoint(P) + message
	hashTag := append(t, bytesFromPoint(*P)...)
	hashTag = append(hashTag, message...)
	k0 := new(big.Int).Mod(intFromBytes(taggedHash("BIP0340/nonce", hashTag)), n)
	if k0.Cmp(big.NewInt(0)) == 0 {
		panic("Failure. This happens only with negligible probability.")
	}
	R := mul(&G, k0)
	assertNotInfinity(R)

	var k *big.Int
	if hasEvenY(R) {
		k = k0
	} else {
		k = new(big.Int).Sub(n, k0)
	}

	// hashTag2 = bytesFromPoint(R) + bytesFromPoint(P) + message
	hashTag2 := append(bytesFromPoint(*R), bytesFromPoint(*P)...)
	hashTag2 = append(hashTag2, message...)
	tagged := taggedHash("BIP0340/challenge", hashTag2)
	e := new(big.Int).Mod(intFromBytes(tagged), n)

	sig := bytesFromPoint(*R)
	sig = append(sig, bytesFromInt(new(big.Int).Mod(
		new(big.Int).Add(k, new(big.Int).Mul(e, d)),
		n,
	))...)

	sig2 := make([]byte, 64)
	copy(sig2, sig) // that's mutability for ya

	if !schnorrVerify(message, bytesFromPoint(*P), sig2) {
		panic("The created signature does not pass verification.")
	}
	return sig
}

func schnorrVerify(message, pubkey, sig []byte) bool {
	if len(pubkey) != 32 {
		panic(fmt.Sprintf("The public key must be a 32-byte array, got %d.", len(pubkey)))
	} else if len(sig) != 64 {
		panic(fmt.Sprintf("The signature must be a 64-byte array, got %d.", len(sig)))
	}
	P := liftX(intFromBytes(pubkey))
	r := intFromBytes(sig[:32])
	s := intFromBytes(sig[32:])

	if P == nil || r.Cmp(p) >= 0 || s.Cmp(n) >= 0 {
		return false
	}

	// hashTag = sig[:32] + pubkey + message
	hashTag := sig[:32]
	hashTag = append(hashTag, pubkey...)
	hashTag = append(hashTag, message...)

	e := new(big.Int).Mod(
		intFromBytes(taggedHash(
			"BIP0340/challenge",
			hashTag,
		)),
		n,
	)
	R := add(
		mul(&G, s),
		mul(P, new(big.Int).Sub(n, e)),
	)
	return R != nil && hasEvenY(R) && x(R).Cmp(r) == 0
}

// aux

func bytesFromHex(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func hexFromBytes(b []byte) string {
	return hex.EncodeToString(b)
}

// it's Testing Time

func main() {
	fmt.Println("Hello, World!")

	file, err := os.Open("test-vectors.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	r := csv.NewReader(file)

	allPassed := true

	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		index := row[0]
		seckeyHex := row[1]
		pubkeyHex := row[2]
		auxRandHex := row[3]
		msgHex := row[4]
		sigHex := row[5]
		resultStr := row[6]
		comment := row[7]

		pubkey := bytesFromHex(pubkeyHex)
		msg := bytesFromHex(msgHex)
		sig := bytesFromHex(sigHex)
		result := resultStr == "TRUE"

		fmt.Printf("Test vector %s:\n", index)
		if seckeyHex != "" {
			seckey := bytesFromHex(seckeyHex)
			pubkeyActual := pubkeyGen(seckey)
			// compare pubkey with pubkeyActual
			if !bytes.Equal(pubkey, pubkeyActual) {
				fmt.Println(" * Failed key generation.")
				fmt.Println("   Expected key:", hexFromBytes(pubkey))
				fmt.Println("     Actual key:", hexFromBytes(pubkeyActual))
				allPassed = false
			}
			auxRand := bytesFromHex(auxRandHex)
			sigActual := schnorrSign(msg, seckey, auxRand)
			if bytes.Equal(sig, sigActual) {
				fmt.Println(" * Passed signing test.")
			} else {
				fmt.Println(" * Failed signing test.")
				fmt.Println("   Expected signature:", hexFromBytes(sig))
				fmt.Println("     Actual signature:", hexFromBytes(sigActual))
				allPassed = false
			}
		}
		resultActual := schnorrVerify(msg, pubkey, sig)
		if resultActual == result {
			fmt.Println(" * Passed verification test.")
		} else {
			fmt.Println(" * Failed verification test.")
			fmt.Println("   Expected verification result:", result)
			fmt.Println("     Actual verification result:", resultActual)
			if comment != "" {
				fmt.Println("   Comment:", comment)
			}
			allPassed = false
		}
	}

	if allPassed {
		fmt.Println("\nAll tests passed.")
	} else {
		fmt.Println("\nSome tests failed.")
	}
}
