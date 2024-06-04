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

local handleTypes = {
	EVENT = function(request: net.WebSocket, event: any) end,
	REQ = function(request: net.WebSocket, ...: any) end,
	CLOSE = function(request: net.WebSocket, id: string) end,
}

local function handleRequest(request: net.WebSocket)
	local event = request.next() :: string
	if not event then
		request.send(msg.invalid "empty request, expected body")
		return
	elseif event == "" then
		request.send(msg.invalid "empty body, expected message")
		return
	elseif maybeObject(event) then
		request.send(
			msg.invalid "message appears to be a json object, expected array"
		)
		return
	elseif not maybeArray(event) then
		request.send(msg.invalid "message must be a json array")
		return
	end

	local ok, decoded = pcall(jsonDecode, event)
	if not ok then
		request.send(msg.invalid "message json could not be decoded")
		return
	elseif #decoded == 0 then -- May be an empty array or an object
		request.send(msg.invalid "message array is empty")
		return
	elseif #decoded < 2 then
		request.send(
			msg.invalid "message array is too short, must contain at least 2 elements"
		)
		return
	end

	local first = decoded[1]
	if type(first) ~= "string" then
		request.send(
			msg.invalid "message array first element (message type) must be a string"
		)
		return
	elseif first ~= "EVENT" and first ~= "REQ" and first ~= "CLOSE" then
		request.send(
			msg.invalid "invalid message type - must be of EVENT, REQ, CLOSE"
		)
		return
	end

	local contents = { select(2, table.unpack(decoded)) }

	if first == "EVENT" then
		if #contents ~= 1 then
			request.send(
				msg.invalid "EVENT message can only contain 1 element (event data)"
			)
			return
		end

		local eventData = contents[1]

		if type(eventData) ~= "table" then
			request.send(msg.invalid "event data must be a json object")
			return
		elseif #eventData > 0 then
			request.send(
				msg.invalid "event data appears to be a json array, expected object"
			)
			return
		end

		local allowedFields =
			{ "id", "pubkey", "created_at", "kind", "tags", "content", "sig" }
		local originalLen = #allowedFields

		for k, v in eventData do
			local found = table.find(allowedFields, k)
			if found then
				table.remove(allowedFields, found)
			else
				request.send(
					msg.invalid(
						`invalid field in event data: {k}. must be one of {table.concat(
							allowedFields,
							", "
						)}`
					)
				)
				return
			end
		end

		local currentLen = #allowedFields

		if originalLen == currentLen then
			request.send(
				msg.invalid "event data must not be empty"
			)
			return
		elseif currentLen > 0 then
			request.send(
				msg.invalid(
					`missing field{if #allowedFields > 1 then "s" else ""} in event data: {table.concat(
						allowedFields,
						", "
					)}`
				)
			)
			return
		end
	elseif first == "REQ" then
		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			request.send(msg.invalid "subscription id must be a string")
			return
		elseif subscriptionId == "" then
			request.send(
				msg.invalid "subscription id cannot be an empty string"
			)
			return
		end
	elseif first == "CLOSE" then
		if #contents ~= 1 then
			request.send(
				msg.invalid "CLOSE message can only contain 1 element (subscription id)"
			)
			return
		end

		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			request.send(msg.invalid "subscription id must be a string")
			return
		elseif subscriptionId == "" then
			request.send(
				msg.invalid "subscription id cannot be an empty string"
			)
			return
		end
	end
end

local function handleWebSocket(request: net.WebSocket)
	while true do
		handleRequest(request)
	end
end

net.serve(3223, {
	handleRequest = function()
		return "Please use a Nostr client to connect."
	end,
	handleWebSocket = handleWebSocket,
})

print "http://localhost:3223"
