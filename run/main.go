package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	lc "github.com/Heliodex/litecode"
)

func global_verify(args lc.Args) (r lc.Rets, err error) {
	hashs, pks, sigs := args.GetString(), args.GetString(), args.GetString()

	hash, err := hex.DecodeString(hashs)
	if err != nil {
		return nil, errors.New("invalid hash hex")
	}

	pk, err := hex.DecodeString(pks)
	if err != nil {
		return nil, errors.New("invalid public key hex")
	}

	sig, err := hex.DecodeString(sigs)
	if err != nil {
		return nil, errors.New("invalid signature hex")
	}

	res, err := schnorrVerify(hash, pk, sig)
	if err != nil {
		return nil, fmt.Errorf("error verifying hash: %w", err)
	}
	return lc.Rets{res}, nil
}

func global_sha256(args lc.Args) (r lc.Rets, err error) {
	msg := args.GetString()

	hash := crypto.SHA256.New()
	hash.Write([]byte(msg))

	hex := hex.EncodeToString(hash.Sum(nil))
	return lc.Rets{hex}, nil
}

func global_ishex(args lc.Args) (r lc.Rets, err error) {
	s := args.GetString()

	_, err = hex.DecodeString(s)
	return lc.Rets{err == nil}, nil
}

func global_print(args lc.Args) (r lc.Rets, err error) {
	a := args.List

	for i, v := range a {
		fmt.Print(v)
		if i < len(a)-1 {
			fmt.Print(" ")
		}
	}
	fmt.Println()

	return nil, nil
}

func json_encodestring(args lc.Args) (r lc.Rets, err error) {
	obj := args.GetString()

	res, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("error encoding string: %w", err)
	}

	return lc.Rets{string(res)}, nil
}

func json_encodearray(args lc.Args) (r lc.Rets, err error) {
	obj := args.GetTable()

	arr := obj.Array
	if arr == nil {
		return lc.Rets{"[]"}, nil
	}

	res, err := json.Marshal(arr)
	if err != nil {
		return nil, fmt.Errorf("error encoding array: %w", err)
	}

	return lc.Rets{string(res)}, nil
}

func json_decode(args lc.Args) (r lc.Rets, err error) {
	obj := args.GetString()

	var res any
	err = json.Unmarshal([]byte(obj), &res)
	if err != nil {
		return nil, fmt.Errorf("error decoding: %w", err)
	}

	switch v := res.(type) {
	case bool, float64, string, nil:
		return lc.Rets{v}, nil
	case []any:
		return lc.Rets{&lc.Table{Array: v}}, nil
	case map[string]any:
		h := make(map[any]any, len(v))
		for k, v := range v {
			h[k] = v
		}

		return lc.Rets{&lc.Table{Hash: h}}, nil
	}
	return nil, errors.New("unsupported type")
}

var libjson = lc.NewTable([][2]any{
	lc.MakeFn("encodestring", json_encodestring),
	lc.MakeFn("encodearray", json_encodearray),
	lc.MakeFn("decode", json_decode),
})

func load(f string) (r lc.Rets, err error) {
	bytecode, err := lc.Compile(f)
	if err != nil {
		return
	}

	deserialised, err := lc.Deserialise(bytecode)
	if err != nil {
		return
	}

	co, _ := lc.Load(deserialised, f, 1, map[any]any{
		"verify": lc.MakeFn("verify", global_verify)[1],
		"sha256": lc.MakeFn("sha256", global_sha256)[1],
		"ishex":  lc.MakeFn("ishex", global_ishex)[1],
		"print":  lc.MakeFn("print", global_print)[1],

		"json": libjson,
	})

	return co.Resume()
}

func main() {
	_, err := load("test.luau")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
}
