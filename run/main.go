package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"

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

func global_ishashfield(args lc.Args) (r lc.Rets, err error) {
	s := args.GetString()

	// if # followed by [a-zA-Z]
	if len(s) < 2 || s[0] != '#' || (s[1] < 'a' || s[1] > 'z') && (s[1] < 'A' || s[1] > 'Z') {
		return lc.Rets{false}, nil
	}
	return lc.Rets{true}, nil
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

func tconvert(obj any) (any, error) {
	switch v := obj.(type) {
	case bool, float64, string, nil:
		return v, nil
	case []any:
		arr := make([]any, len(v))
		for i, v2 := range v {
			c, err := tconvert(v2)
			if err != nil {
				return nil, err
			}
			arr[i] = c
		}

		return &lc.Table{Array: arr}, nil
	case map[string]any:
		h := make(map[any]any, len(v))
		for k, v := range v {
			c, err := tconvert(v)
			if err != nil {
				return nil, err
			}
			h[k] = c
		}

		return &lc.Table{Hash: h}, nil
	}
	return nil, errors.New("unsupported type")
}

func json_decode(args lc.Args) (r lc.Rets, err error) {
	obj := args.GetString()

	var res any
	err = json.Unmarshal([]byte(obj), &res)
	if err != nil {
		return lc.Rets{false, fmt.Sprintf("error decoding json")}, nil
	}

	c, err := tconvert(res)
	if err != nil {
		return nil, err
	}

	return lc.Rets{true, c}, nil
}

var libjson = lc.NewTable([][2]any{
	lc.MakeFn("encodestring", json_encodestring),
	lc.MakeFn("encodearray", json_encodearray),
	lc.MakeFn("decode", json_decode),
})

func serve(port float64, reqHandler func(a2 ...any) string, wsHandler func(a2 ...any)) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Upgrade") != "websocket" {
			res := reqHandler()
			w.Write([]byte(res))
			return
		}

		var server websocket.Server

		server.Handshake = func(config *websocket.Config, req *http.Request) error {
			return nil
		}

		server.Handler = func(ws *websocket.Conn) {
			send := func(args lc.Args) (r lc.Rets, err error) {
				data := args.GetString()

				_, err = ws.Write([]byte(data))
				return nil, err
			}
			next := func(args lc.Args) (r lc.Rets, err error) {
				data := make([]byte, 1024)
				n, err := ws.Read(data)
				if err != nil {
					return nil, err
				}

				return lc.Rets{string(data[:n])}, nil
			}

			wsHandler(lc.NewTable([][2]any{
				lc.MakeFn("send", send),
				lc.MakeFn("next", next),
			}))
		}

		server.ServeHTTP(w, req)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", int(port)), handler)
}

func net_serve(args lc.Args) (r lc.Rets, err error) {
	port := args.GetNumber()
	opts := args.GetTable()

	request := opts.GetHash("request")
	websocket := opts.GetHash("websocket")

	reqHandler, ok := request.(lc.Function)
	if !ok {
		return nil, errors.New("invalid request handler")
	}

	wsHandler, ok := websocket.(lc.Function)
	if !ok {
		return nil, errors.New("invalid websocket handler")
	}

	return nil, serve(
		port,
		func(a2 ...any) string {
			ret, err := (*reqHandler)(args.Co, a2...)
			if err != nil {
				args.Co.Error(err)
			} else if len(ret) == 0 {
				return ""
			}

			s, ok := ret[0].(string)
			if !ok {
				args.Co.Error(fmt.Errorf("invalid response"))
			}

			return s
		},
		func(a2 ...any) {
			if _, err := (*wsHandler)(args.Co, a2...); err != nil {
				args.Co.Error(err)
			}
		})
}

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
		"verify":      lc.MakeFn("verify", global_verify)[1],
		"sha256":      lc.MakeFn("sha256", global_sha256)[1],
		"ishex":       lc.MakeFn("ishex", global_ishex)[1],
		"ishashfield": lc.MakeFn("ishashfield", global_ishashfield)[1],
		"print":       lc.MakeFn("print", global_print)[1],

		"json":  libjson,
		"serve": lc.MakeFn("serve", net_serve)[1],
	})

	return co.Resume()
}

func main() {
	_, err := load("../main.luau")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
}
