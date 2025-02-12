declare verify: (hash: string, pk: string, sig: string) -> boolean
declare sha256: (data: string) -> string

declare json: {
	encodestring: (data: string) -> string,
	encodearray: (data: { any }) -> string,
	decode: (json: string) -> (boolean, any),
}

export type Websocket = {
	send: (data: string) -> (),
	next: () -> string,
}

declare serve: (
	port: number,
	handlers: {
		request: () -> string,
		websocket: (ws: Websocket) -> (),
	}
) -> ()
