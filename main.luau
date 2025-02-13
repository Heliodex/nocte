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
		local encodedTag = json.encodearray(v)
		if encodedTag == "{}" then encodedTag = "[]" end
		table.insert(encodedTags, encodedTag)
	end

	local event = `[0,"{pubkey}",{created_at},{kind},[{table.concat(
		encodedTags,
		","
	)}],{json.encodestring(content)}]`

	return sha256(event)
end

local function ishex(str: string) return string.match(str, "^[0-9a-f]+$") end
local function ishashfield(str: string) return string.match(str, "^#[a-zA-Z]$") end

local msg = {
	event = function() end,
	ok = function(id: string, ok: boolean, message: string)
		return json.encodearray { "OK", id, ok, message }
	end,
	eose = function() end,
	closed = function() end,
	notice = function(message: string)
		return json.encodearray { "NOTICE", message }
	end,
	error = function(message: string)
		return json.encodearray { "NOTICE", `error: {message}` }
	end,
	invalid = function(message: string)
		return json.encodearray { "NOTICE", `invalid: {message}` }
	end,
}

local lbracket, rbracket, lbrace, rbrace =
	string.byte "[", string.byte "]", string.byte "{", string.byte "}"

-- array starts and ends with square brackets
local function maybeArray(json: string)
	local first, last = string.byte(json, 1), string.byte(json, -1)
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
		elseif not ishex(id) then
			return "event id must be a lowercase hexadecimal string"
		end
		return
	end,
	pubkey = function(pubkey: string): string?
		if type(pubkey) ~= "string" then
			return "event pubkey must be a string"
		elseif #pubkey ~= 64 then
			return "event pubkey must be 64 characters long"
		elseif not ishex(pubkey) then
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
		if type(tags) ~= "table" then return "event tags must be an array" end

		for i, v in tags do
			if type(i) ~= "number" then
				return "invalid non-numerical key in tags array"
			elseif type(v) ~= "table" then
				return "event tags must be an array of arrays"
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
		elseif not ishex(sig) then
			return "event sig must be a lowercase hexadecimal string"
		end
		return
	end,
}

local function handler(ws: Websocket, subscriptions: { [string]: any })
	local function invalid(message: string) ws.send(msg.invalid(message)) end
	local function ok(id: string, ok: boolean, message: string)
		ws.send(msg.ok(id, ok, message))
	end

	local event = ws.next()
	if not event then
		return
	elseif event == "" then
		invalid "empty body, expected message"
		return
	end

	local trim = string.match(event, "^%s*(.-)%s*$")
	if trim then event = trim end

	if maybeObject(event) then
		invalid "message appears to be a json object, expected array"
		return
	elseif not maybeArray(event) then
		invalid "message must be a json array"
		return
	end

	local ok1, decoded = json.decode(event)
	if not ok1 then
		invalid "message json could not be decoded"
		return
	elseif #decoded == 0 then
		invalid "message array is empty, must contain at least 2 elements"
		return
	elseif #decoded < 2 then
		invalid "message array is too short, must contain at least 2 elements"
		return
	end

	local d = decoded :: { any }

	local first = d[1]
	if type(first) ~= "string" then
		invalid "message array first element (message type) must be a string"
		return
	elseif first ~= "EVENT" and first ~= "REQ" and first ~= "CLOSE" then
		invalid(
			`invalid message type: "{first}". must be one of EVENT, REQ, CLOSE`
		)
		return
	end

	local contents = table.clone(d)
	table.remove(contents, 1)

	if first == "EVENT" then
		if #contents ~= 1 then
			invalid "EVENT message can only contain 1 element (event data)"
			return
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
			print(eventData)
			invalid "event data must be a json object"
			return
		elseif #(eventData :: any) > 0 then
			invalid "event data appears to be a json array, expected object"
			return
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
				invalid(
					`invalid field in event data: {k}. must be one of {missingFields}`
				)
				return
			end
		end

		local currentLen = #requiredFields

		if originalLen == currentLen then
			invalid "event data must not be empty"
			return
		elseif currentLen > 0 then
			local missingFields = table.concat(requiredFields, ", ")
			invalid(
				`missing field{if #requiredFields > 1 then "s" else ""} in event data: {missingFields}`
			)
			return
		end

		for k, v in eventData do
			local res = checks[k](v)
			if res then
				invalid(res)
				return
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

		local res = verify(eventData.id, eventData.pubkey, eventData.sig)
		if not res then
			return ok(
				eventData.id,
				false,
				"event sig does not match the public key"
			)
		end

		-- the event is valid

		-- do something with it

		return ok(eventData.id, true, "")
	elseif first == "REQ" then
		if #contents ~= 2 then
			invalid "EVENT message must contain 2 or more elements (subscription id, filters...)"
			return
		end

		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			invalid "subscription id must be a string"
			return
		elseif subscriptionId == "" then
			invalid "subscription id cannot be an empty string"
			return
		elseif #subscriptionId > 64 then
			invalid "subscription id cannot be longer than 64 characters"
			return
		end

		local filters = { select(2, table.unpack(contents)) }
		local allowedFields =
			{ "ids", "authors", "kinds", "since", "until", "limit" }

		for _, filter in filters do
			if type(filter) ~= "table" then
				invalid "filter must be a json object"
				return
			elseif #(filter :: any) > 0 then
				invalid "filter appears to be a json array, expected object"
				return
			end

			for k, v in filter do
				if
					not table.find(allowedFields, k :: string)
					and not ishashfield(k)
				then
					local missingFields = table.concat(allowedFields, ", ")
					invalid(
						`invalid field in filter: {k}. must be one of {missingFields}, or # followed by a letter`
					)
					return
				end
			end
		end
	elseif first == "CLOSE" then
		if #contents ~= 1 then
			invalid "CLOSE message can only contain 1 element (subscription id)"
			return
		end

		local subscriptionId = contents[1]

		if type(subscriptionId) ~= "string" then
			invalid "subscription id must be a string"
			return
		elseif subscriptionId == "" then
			invalid "subscription id cannot be an empty string"
			return
		elseif #subscriptionId > 64 then
			invalid "subscription id cannot be longer than 64 characters"
			return
		elseif not subscriptions[subscriptionId] then
			invalid "subscription id does not exist"
			return
		end

		subscriptions[subscriptionId] = nil
	end
	return nil
end

local function handleWebsocket(ws: Websocket)
	local subscriptions = {}
	while true do
		handler(ws, subscriptions)
	end
end

print "http://localhost:3223"

serve(3223, {
	request = function() return "Please use a Nostr client to connect." end,
	websocket = handleWebsocket,
})
