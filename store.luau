local function deepCopy(original: { [any]: any })
	local copy = {}
	for k, v in original do
		if type(v) == "table" then
			v = deepCopy(v)
		end
		copy[k] = v
	end
	return copy
end

type Serialisable = string | number | boolean | { [Serialisable]: Serialisable }

export type Store<K, V> = {
	rawData: { [K]: V },
	set: (key: K, value: V) -> (),
	get: (key: K) -> V,
	dump: () -> { [Serialisable]: Serialisable },
	serialise: () -> string,
}

type StoreImpl<K, V> = {
	new: () -> Store<K, V>,
	fromSerialised: (data: string) -> Store<K, V>,
}

local Store: StoreImpl<any, any> = {} :: StoreImpl<any, any>

-- serialisation
local function serProperty<V>(prop: V): string
	if type(prop) == "string" then
		return `[{#prop}]{prop}`
	elseif type(prop) == "number" then
		return tostring(prop)
	elseif type(prop) == "boolean" then
		return if prop then "t" else "f"
	elseif type(prop) == "table" then
		local str = "{"
		for k, v in prop do
			str ..= `{serProperty(k)}:{serProperty(v)},`
		end
		return str .. "}"
	end
	error(`Cannot serialise value of type {type(prop)}`)
end

-- deserialisation
local function deserialiseStore(bk: string): { [Serialisable]: Serialisable }
	local i = 1
	local char = string.sub(bk, i, i)

	local function increment()
		i += 1
		char = string.sub(bk, i, i)
	end

	local function getString(): string
		-- string of the form [n]string, the part inside the brackets is the length of the string
		local stringLen = string.match(bk, "%[(%d+)%]", i)
		local numStringLen = tonumber(stringLen)
		if stringLen and numStringLen then
			i += 1 + #stringLen
			local keyEnd = i + numStringLen

			local key = ""

			while i < keyEnd do
				i += 1
				key ..= string.sub(bk, i, i)
			end

			return key
		end
		error(`Invalid key length, expected number, got {stringLen}`)
	end

	local function getNumber(): number
		-- number of the form... number
		local num = string.match(bk, "%d+", i)
		local numNum = tonumber(num) -- *sense your stimulates*
		if num and numNum then
			i += #num - 1
			return numNum
		end
		error(`Invalid number, expected number, got {num}`)
	end

	local getTable

	local function getProperty(): Serialisable
		if char == "t" then
			return true
		elseif char == "f" then
			return false
		elseif tonumber(char) then
			return getNumber()
		elseif char == "[" then
			return getString()
		elseif char == "{" then
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
		if char ~= ":" then
			error(`Expected colon after key, got {char} at {i}`)
		end
		increment()

		value = getProperty()

		-- match end
		increment()
		if char ~= "," then
			error(`Expected value end indicator after value, got {char} at {i}`)
		end
		increment()

		return key, value
	end

	function getTable(): { [Serialisable]: Serialisable }
		local tableData = {}

		while true do
			-- to start, we're in a key
			increment()
			local key, value = matchKeyValuePair()
			tableData[key] = value

			if char == "}" then
				break
			end
		end

		return tableData
	end

	return getTable()
end

local function createStore<K, V>(data: { [K]: V }): Store<K, V>
	local store = {
		rawData = data,
	}
	local keyType = ""

	function store.set(key: K, value: V)
		-- todo: have table keys work properly

		if keyType == "" then
			keyType = type(key)
		elseif type(key) ~= keyType then
			error(`Expected key type to be {keyType}, got {type(key)}`)
		end

		if type(value) == "table" then
			value = deepCopy(value)
		end

		store.rawData[key] = value
	end

	function store.get(key: K): V
		local value = store.rawData[key]
		if type(value) == "table" then
			return deepCopy(value)
		end
		return value
	end

	function store.dump(): { [Serialisable]: Serialisable }
		return deepCopy(store.rawData)
	end

	function store.serialise(): string
		return serProperty(store.rawData)
	end

	return store
end

function Store.new(): Store<any, any>
	return createStore {}
end

function Store.fromSerialised(data: string): Store<any, any>
	return createStore(deserialiseStore(data))
end

return Store
