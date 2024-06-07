local net = require "@lune/net"
local process = require "@lune/process"
local serde = require "@lune/serde"
local sha256 = require "sha"

local function jsonEncode(data: any): string
	return serde.encode("json", data)
end

local function jsonDecode(data: string)
	return serde.decode("json", data)
end

local function isHex(str: string)
	return string.match(str, "^[0-9a-f]+$")
end

local function bytesToHex(bytes: { number })
	local hex = ""
	for _, v in bytes do
		hex ..= string.format("%02x", v)
	end
	return hex
end

local function hashEvent(
	pubkey: string,
	created_at: number,
	kind: number,
	tags: { { string } },
	content: string
)
	-- JSON serialisation may cause issues due to empty arrays being serialised as empty objects instead
	local encodedTags = {}
	for _, v in tags do
		local encodedTag = jsonEncode(v)
		if encodedTag == "{}" then
			encodedTag = "[]"
		end
		table.insert(encodedTags, encodedTag)
	end

	local event = `[0,"{pubkey}",{created_at},{kind},[{table.concat(
		encodedTags,
		","
	)}],{jsonEncode(content)}]`

	return bytesToHex(sha256(event))
end

local msg = {
	event = function() end,
	ok = function(id: string, ok: boolean, message: string)
		return jsonEncode({ "OK", id, ok, message } :: { any })
	end,
	eose = function() end,
	closed = function() end,
	notice = function(message: string)
		return jsonEncode { "NOTICE", message }
	end,
	error = function(message: string)
		return jsonEncode { "NOTICE", `error: {message}` }
	end,
	invalid = function(message: string)
		return jsonEncode { "NOTICE", `invalid: {message}` }
	end,
}

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

local checks = {
	id = function(id: string): string?
		if type(id) ~= "string" then
			return "event id must be a string"
		elseif #id ~= 64 then
			return "event id must be 64 characters long"
		elseif not isHex(id) then
			return "event id must be a lowercase hexadecimal string"
		end
		return
	end,
	pubkey = function(pubkey: string): string?
		if type(pubkey) ~= "string" then
			return "event pubkey must be a string"
		elseif #pubkey ~= 64 then
			return "event pubkey must be 64 characters long"
		elseif not isHex(pubkey) then
			return "event pubkey must be a lowercase hexadecimal string"
		end
		return
	end,
	created_at = function(created_at: number): string?
		if type(created_at) ~= "number" then
			return "event created_at must be a number"
		elseif created_at % 1 ~= 0 then
			return "event created_at must be an integer"
		end
		return
	end,
	kind = function(kind: number): string?
		if type(kind) ~= "number" then
			return "event kind must be a number"
		elseif kind % 1 ~= 0 then
			return "event kind must be an integer"
		elseif kind < 0 or kind > 65535 then
			return "event kind must be between 0 and 65535"
		end
		return
	end,
	tags = function(tags: { { string } }): string?
		for i, v in tags do
			if type(i) ~= "number" then
				return "invalid non-numerical key in tags array"
			end
			for i2, v2 in v do
				if type(i) ~= "number" then
					return "invalid non-numerical key in tag"
				elseif type(v2) ~= "string" then
					return "tag must be an array of strings"
				end
			end
		end
		return
	end,
	content = function(content: string): string?
		if type(content) ~= "string" then
			return "event content must be a string"
		end
		return
	end,
	sig = function(sig: string): string?
		if type(sig) ~= "string" then
			return "event sig must be a string"
		elseif #sig ~= 128 then
			return "event sig must be 128 characters long"
		elseif not isHex(sig) then
			return "event sig must be a lowercase hexadecimal string"
		end
		return
	end,
}

local handleTypes = {
	EVENT = function(request: net.WebSocket, event: any)
		print "EVENT"
	end,
	REQ = function(request: net.WebSocket, ...: any)
		print "REQ"
	end,
	CLOSE = function(request: net.WebSocket, id: string)
		print "CLOSE"
	end,
}

local function handleRequest(
	request: net.WebSocket,
	subscriptions: { [string]: any }
): nil
	local function invalid(message: string)
		request.send(msg.invalid(message))
	end
	local function ok(id: string, ok: boolean, message: string)
		request.send(msg.ok(id, ok, message))
	end

	local event = request.next() :: string
	if not event then
		return
	elseif event == "" then
		return invalid "empty body, expected message"
	elseif maybeObject(event) then
		return invalid "message appears to be a json object, expected array"
	elseif not maybeArray(event) then
		return invalid "message must be a json array"
	end

	local ok1, decoded = pcall(jsonDecode, event)
	if not ok1 then
		return invalid "message json could not be decoded"
	elseif #decoded == 0 then
		return invalid "message array is empty, must contain at least 2 elements"
	elseif #decoded < 2 then
		return invalid "message array is too short, must contain at least 2 elements"
	end

	local first = decoded[1]
	if type(first) ~= "string" then
		return invalid "message array first element (message type) must be a string"
	elseif first ~= "EVENT" and first ~= "REQ" and first ~= "CLOSE" then
		return invalid(
			`invalid message type: {first}. must be one of EVENT, REQ, CLOSE`
		)
	end

	local contents = { select(2, table.unpack(decoded)) }

	if first == "EVENT" then
		if #contents ~= 1 then
			return invalid "EVENT message can only contain 1 element (event data)"
		end

		local eventData: {
			id: string,
			pubkey: string,
			created_at: number,
			kind: number,
			tags: { { string } },
			content: string,
			sig: string,
		} =
			contents[1]

		if type(eventData) ~= "table" then
			return invalid "event data must be a json object"
		elseif #(eventData :: any) > 0 then
			return invalid "event data appears to be a json array, expected object"
		end

		local requiredFields =
			{ "id", "pubkey", "created_at", "kind", "tags", "content", "sig" }
		local originalLen = #requiredFields

		for k, v in eventData do
			local found = table.find(requiredFields, k :: string)
			if found then
				table.remove(requiredFields, found)
			else
				local missingFields = table.concat(requiredFields, ", ")
				return invalid(
					`invalid field in event data: {k}. must be one of {missingFields}`
				)
			end
		end

		local currentLen = #requiredFields

		if originalLen == currentLen then
			return invalid "event data must not be empty"
		elseif currentLen > 0 then
			local missingFields = table.concat(requiredFields, ", ")
			return invalid(
				`missing field{if #requiredFields > 1 then "s" else ""} in event data: {missingFields}`
			)
		end

		for k, v in eventData do
			local res = checks[k](v)
			if res then
				return invalid(res)
			end
		end

		if
			hashEvent(
				eventData.pubkey,
				eventData.created_at,
				eventData.kind,
				eventData.tags,
				eventData.content
			) ~= eventData.id
		then
			return ok(
				eventData.id,
				false,
				"event id does not match the sha-256 hash of the serialised event data"
			)
		end

		local res = process.spawn("./ext/nocte-external", {
			"verify",
			eventData.id,
			eventData.pubkey,
			eventData.sig,
		})

		if not res.ok then
			return ok(
				eventData.id,
				false,
				"event sig does not match the public key"
			)
		end

		-- the event is valid

		handleTypes[first](request, eventData)

		return ok(eventData.id, true, "")
	elseif first == "REQ" then
		if #contents ~= 2 then
			return invalid "EVENT message must contain 2 or more elements (subscription id, filters...)"
		end

		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			return invalid "subscription id must be a string"
		elseif subscriptionId == "" then
			return invalid "subscription id cannot be an empty string"
		elseif #subscriptionId > 64 then
			return invalid "subscription id cannot be longer than 64 characters"
		end

		local filters = { select(2, table.unpack(contents)) }
		local allowedFields =
			{ "ids", "authors", "kinds", "since", "until", "limit" }

		for _, filter in filters do
			if type(filter) ~= "table" then
				return invalid "filter must be a json object"
			elseif #(filter :: any) > 0 then
				return invalid "filter appears to be a json array, expected object"
			end

			for k, v in filter do
				if
					not table.find(allowedFields, k :: string)
					and not string.match(k, "^#[a-zA-Z]$")
				then
					local missingFields = table.concat(allowedFields, ", ")
					return invalid(
						`invalid field in filter: {k}. must be one of {missingFields}, or # followed by a letter`
					)
				end
			end
		end
	elseif first == "CLOSE" then
		if #contents ~= 1 then
			return invalid "CLOSE message can only contain 1 element (subscription id)"
		end

		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			return invalid "subscription id must be a string"
		elseif subscriptionId == "" then
			return invalid "subscription id cannot be an empty string"
		elseif #subscriptionId > 64 then
			return invalid "subscription id cannot be longer than 64 characters"
		elseif not subscriptions[subscriptionId] then
			return invalid "subscription id does not exist"
		end

		subscriptions[subscriptionId] = nil
	end
	return nil
end

local function handleWebSocket(request: net.WebSocket)
	local subscriptions = {}
	while true do
		local ok, err = pcall(handleRequest, request, subscriptions)
		if not ok then
			print("error occured", err)
			request.send(msg.error "internal server error")
		end
	end
end

net.serve(3223, {
	handleRequest = function()
		return "Please use a Nostr client to connect."
	end,
	handleWebSocket = handleWebSocket,
})

print "http://localhost:3223"
