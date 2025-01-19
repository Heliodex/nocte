declare verify: (hash: string, pk: string, sig: string) -> boolean
declare sha256: (data: string) -> string
declare ishex: (data: string) -> boolean

declare json: {
	encodestring: (data: string) -> string,
	encodearray: (data: { any }) -> string,
	decode: (json: string) -> any,
}
