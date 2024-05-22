local net = require "@lune/net"
local serde = require "@lune/serde"

local function jsonEncode(data: any): string
	return serde.encode("json", data)
end

local function jsonDecode(data: string)
	return serde.decode("json", data)
end

local msg = {
	event = function() end,
	ok = function() end,
	eose = function() end,
	closed = function() end,
	notice = function(message: string)
		return jsonEncode { "NOTICE", message }
	end,
	invalid = function(message: string)
		return jsonEncode { "NOTICE", `invalid: {message}` }
	end,
}

local function handleMessage(request: net.WebSocket, event: { any })
	request.send(msg.notice "success, unimplemented")
end

local lbracket, rbracket, lbrace, rbrace =
	string.byte "[", string.byte "]", string.byte "{", string.byte "}"

-- array starts and ends with square brackets
local function maybeArray(json: string)
	local first, last = string.byte(json, 1), string.byte(json, #json)
	return first == lbracket and last == rbracket
end

-- object starts and ends with curly braces
local function maybeObject(json: string)
	local first, last = string.byte(json, 1), string.byte(json, #json)
	return first == lbrace and last == rbrace
end

local function handleWebSocket(request: net.WebSocket)
	while true do
		local event = request.next() :: string
		if not event then
			request.send(msg.invalid "empty request")
			continue
		elseif event == "" then
			request.send(msg.invalid "empty message")
			continue
		elseif maybeObject(event) then
			request.send(
				msg.invalid "message appears to be a json object, expected array"
			)
			continue
		elseif not maybeArray(event) then
			request.send(msg.invalid "message must be a json array")
			continue
		end

		local ok, decoded = pcall(jsonDecode, event)
		if not ok then
			request.send(msg.invalid "message json could not be decoded")
			continue
		elseif #decoded == 0 then -- May be an empty array or an object
			request.send(msg.invalid "message array is empty")
			continue
		elseif #decoded < 2 then
			request.send(
				msg.invalid "message array is too short, must contain at least 2 elements"
			)
			continue
		end

		local first = decoded[1]
		if type(first) ~= "string" then
			request.send(
				msg.invalid "message array first element must be a string"
			)
			continue
		elseif first ~= "EVENT" and first ~= "REQ" and first ~= "CLOSE" then
			request.send(
				msg.invalid "invalid message type - must be of EVENT, REQ, CLOSE"
			)
			continue
		end

		handleMessage(request, decoded)
	end
end

net.serve(3223, {
	handleRequest = function()
		return "Please use a Nostr client to connect."
	end,
	handleWebSocket = handleWebSocket,
})

print "http://localhost:3223"
