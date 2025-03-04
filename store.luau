export type Serialisable =
	string
	| number
	| boolean
	| { [Serialisable]: Serialisable }

-- serialisation
local function serProperty<V>(prop: V)
	if type(prop) == "string" then
		return `[{#prop}]{prop}`
	elseif type(prop) == "number" then
		return tostring(prop)
	elseif type(prop) == "boolean" then
		return if prop then "t" else "f"
	elseif type(prop) == "table" then
		local strings = { "{" }
		for k, v in prop do
			table.insert(strings, `{serProperty(k)}:{serProperty(v)},`)
		end
		table.insert(strings, "}")
		return table.concat(strings)
	end
	error(`Cannot serialise value of type {type(prop)}`)
end

-- deserialisation
local function deserialiseStore(bk): { [Serialisable]: Serialisable }
	local i = 1
	local char = string.sub(bk, i, i)
	if char ~= "{" then error(`Expected store start, got {char} at {i}`) end

	local function compare(c: string) return char == c end

	local function increment()
		i += 1
		char = string.sub(bk, i, i)
	end
	increment()

	local function getString()
		-- string of the form [n]string, the part inside the brackets is the length of the string
		local stringLen = string.match(bk, "%[(%d+)%]", i)
		if stringLen then
			i += 1 + #stringLen

			local pi = i
			i += tonumber(stringLen) or 0
			return string.sub(bk, pi + 1, i)
		end
		error(`Invalid key length, expected number, got {stringLen}`)
	end

	local function getNumber(): number
		-- number of the form... number
		local num = string.match(bk, "%d+", i)
		if num then
			i += #num - 1
			return tonumber(num) or 0
		end
		error(`Invalid number, expected number, got {num}`)
	end

	local getTable

	local function getProperty(): Serialisable
		if compare "t" then
			return true
		elseif compare "f" then
			return false
		elseif tonumber(char) then
			return getNumber()
		elseif compare "[" then
			return getString()
		elseif compare "{" then
			return getTable()
		end

		error(`Expected value, got {char} at {i}`)
	end

	local function matchKeyValuePair(): (Serialisable, Serialisable)
		local key: Serialisable
		local value: Serialisable

		-- to start, we're in a key
		key = getProperty()

		-- match separator
		increment()
		if not compare ":" then
			error(`Expected colon after key, got {char} at {i}`)
		end
		increment()

		value = getProperty()

		-- match end
		increment()
		if not compare "," then
			error(`Expected value end indicator after value, got {char} at {i}`)
		end

		return key, value
	end

	function getTable(): { [Serialisable]: Serialisable }
		local tableData = {}

		while true do
			-- to start, we're in a key
			local key, value = matchKeyValuePair()
			tableData[key] = value
			increment()

			if compare "}" then break end
		end

		return tableData
	end

	return getTable()
end

local function deepCopy(original: any): any
	if type(original) ~= "table" then return original end

	local copy = {}
	for k, v in original do
		copy[k] = deepCopy(v)
	end
	return copy
end
export type Store<K, V> = {
	set: (key: K, value: V) -> (),
	get: (key: K) -> V,
	serialise: () -> string,
}

local function Store<K, V>(serialised: string?): Store<K, V>
	local rawData = (
		if serialised then deserialiseStore(serialised) else {}
	) :: { [K]: V }

	local store = {}
	local keyType = ""

	function store.set(key: K, value: V)
		if keyType == "" then
			keyType = type(key)
			if type(key) == "table" then
				error "Cannot use table as key type (yet?)"
			end
		elseif type(key) ~= keyType then
			error(`Expected key type to be {keyType}, got {type(key)}`)
		end

		rawData[key] = deepCopy(value)
	end

	function store.get(key: K): V return deepCopy(rawData[key]) end

	function store.serialise(): string return serProperty(rawData) end

	return store
end

return Store
