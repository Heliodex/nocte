package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/net/websocket"

	"github.com/Heliodex/coputer/litecode/types"
	"github.com/Heliodex/coputer/litecode/vm"
	"github.com/Heliodex/coputer/litecode/vm/compile"
	"github.com/Heliodex/coputer/litecode/vm/std"
)

func global_verify(args std.Args) (r []types.Val, err error) {
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
	return []types.Val{res}, nil
}

func global_sha256(args std.Args) (r []types.Val, err error) {
	msg := args.GetString()

	hash := crypto.SHA256.New()
	hash.Write([]byte(msg))

	hex := hex.EncodeToString(hash.Sum(nil))
	return []types.Val{hex}, nil
}

func global_print(args std.Args) (r []types.Val, err error) {
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

func json_encodestring(args std.Args) (r []types.Val, err error) {
	obj := args.GetString()

	res, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("error encoding string: %w", err)
	}

	return []types.Val{string(res)}, nil
}

func json_encodearray(args std.Args) (r []types.Val, err error) {
	obj := args.GetTable()

	arr := obj.List
	if arr == nil {
		return []types.Val{"[]"}, nil
	}

	res, err := json.Marshal(arr)
	if err != nil {
		return nil, fmt.Errorf("error encoding array: %w", err)
	}

	return []types.Val{string(res)}, nil
}

func tconvert(obj any) (any, error) {
	switch v := obj.(type) {
	case bool, float64, string, nil:
		return v, nil
	case []any:
		arr := make([]types.Val, len(v))
		for i, v2 := range v {
			c, err := tconvert(v2)
			if err != nil {
				return nil, err
			}
			arr[i] = c
		}

		return &types.Table{List: arr}, nil
	case map[string]any:
		h := make(map[types.Val]types.Val, len(v))
		for k, v := range v {
			c, err := tconvert(v)
			if err != nil {
				return nil, err
			}
			h[k] = c
		}

		return &types.Table{Hash: h}, nil
	}
	return nil, errors.New("unsupported type")
}

func json_decode(args std.Args) (r []types.Val, err error) {
	obj := args.GetString()

	var res any
	err = json.Unmarshal([]byte(obj), &res)
	if err != nil {
		return []types.Val{false, "error decoding json"}, nil
	}

	c, err := tconvert(res)
	if err != nil {
		return nil, err
	}

	return []types.Val{true, c}, nil
}

var libjson = std.NewLib([]types.Function{
	std.MakeFn("encodestring", json_encodestring),
	std.MakeFn("encodearray", json_encodearray),
	std.MakeFn("decode", json_decode),
})

func serve(port float64, reqHandler func(a2 ...types.Val) string, wsHandler func(a2 ...types.Val)) error {
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
			send := func(args std.Args) (r []types.Val, err error) {
				data := args.GetString()

				_, err = ws.Write([]byte(data))
				return nil, err
			}
			next := func(args std.Args) (r []types.Val, err error) {
				data := make([]byte, 1024)
				n, err := ws.Read(data)
				if err != nil {
					return nil, err
				}

				return []types.Val{string(data[:n])}, nil
			}

			wsHandler(std.NewLib([]types.Function{
				std.MakeFn("send", send),
				std.MakeFn("next", next),
			}))
		}

		server.ServeHTTP(w, req)
	})

	return http.ListenAndServe(fmt.Sprintf(":%d", int(port)), handler)
}

func net_serve(args std.Args) (r []types.Val, err error) {
	port := args.GetNumber()
	opts := args.GetTable()

	request := opts.GetHash("request")
	websocket := opts.GetHash("websocket")

	reqHandler, ok := request.(types.Function)
	if !ok {
		return nil, errors.New("invalid request handler")
	}

	wsHandler, ok := websocket.(types.Function)
	if !ok {
		return nil, errors.New("invalid websocket handler")
	}

	return nil, serve(
		port,
		func(a2 ...types.Val) string {
			ret, err := (*reqHandler.Run)(args.Co, a2...)
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
		func(a2 ...types.Val) {
			if _, err := (*wsHandler.Run)(args.Co, a2...); err != nil {
				args.Co.Error(err)
			}
		})
}

func load(f string) (r []types.Val, err error) {
	c := compile.MakeCompiler(1)

	p, err := compile.Compile(c, f)
	if err != nil {
		return
	}

	env := types.Env{
		"json": libjson,
	}

	env.AddFn(std.MakeFn("verify", global_verify))
	env.AddFn(std.MakeFn("sha256", global_sha256))
	env.AddFn(std.MakeFn("print", global_print))

	env.AddFn(std.MakeFn("serve", net_serve))

	co, _ := vm.Load(p, env, types.TestArgs{})

	return co.Resume()
}

func main() {
	_, err := load("../main.luau")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
}
