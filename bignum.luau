-- BigNum Library
-- @author Validark

-- This library implements two's complement signed integers in base 16777216 (2^24)

-- In binary, numbers have place values like so:
-- | -2^4 | 2^3 | 2^2 | 2^1 | 2^0 |
-- | -16's| 8's | 4's | 2's | 1's |

-- In base 16777216, the place values look like this (the leftmost radix is a bit more complicated)
-- | 16777216^4        | 16777216^3      | 16777216^2   | 16777216^1 | 16777216^0 |

-- Hence, each base 16777216 value holds what would be 24 base 2 values, or 3 bytes
-- This means we could hypothetically implement a 64 bit signed integer using 2 2/3 radix

-- These BigNums are initialized with a pre-allocated amount of radix
-- This is because signed integers work in a particular way
-- In order to achieve efficient, signed integers, we basically flip the number line below the negative so
-- we can intentionally overflow one way or the other when adding and subtracting across the 0 boundary

-- Caveats:
-- The most negative number possible can not be used in a division expression
-- 		This is an extreme edge case but it could be encountered if someone turns the DEFAULT_RADIX to 1

local DEFAULT_RADIX = 128 -- Number of places/digits/radix

-- We use 2^24 for two reasons:
--	1) It can be represented by 4 radix in base 2^6
--	2) It is large enough to take advantage of the underlying double construct but small
-- 		enough that the internal operands will not be larger than the largest (consecutive) integer a double can represent: 2^53
-- 		This is the largest internal operand value (before modulo): (DEFAULT_BASE - 1)^2 + DEFAULT_BASE - 1
local DEFAULT_BASE = 2 ^ 24 -- Don't change this

local BigNum = {
	new = function(Number: string) end,
}
BigNum.__index = {}

export type BigNum = typeof(setmetatable({}, BigNum))

local CONSTANTS_VALUE = {
	__index = function(self, i)
		local t = {}
		local j = self.n :: number

		for a = 1, j - 1 do
			t[a] = 0
		end

		t[j] = i

		while t[j] >= self.Base do
			local t_j = t[j]
			local x = t_j % self.Base
			t[j] = x
			j -= 1
			t[j] = (t_j - x) / self.Base
		end

		self[i] = t
		return setmetatable(t, BigNum)
	end,
}

local CONSTANTS_LENGTH = {
	__index = function(self, i)
		local t = setmetatable({ n = i, Base = self.Base }, CONSTANTS_VALUE)
		self[i] = t
		return t
	end,
}

local CONSTANTS = setmetatable({}, { -- Usage: CONSTANTS[BASE][LENGTH][VALUE]
	__index = function(self, i)
		local t = setmetatable({ Base = i }, CONSTANTS_LENGTH)
		self[i] = t
		return t
	end,
})

local function __unm(self: BigNum, Base: number): BigNum
	-- Find the 2's complement

	local Characters = {}

	local j = #self

	for i = 1, j - 1 do
		Characters[i] = Base - self[i] - 1
	end

	local LastValue = Base - self[j]

	while LastValue == Base do
		Characters[j] = 0
		j -= 1
		if j == 0 then
			break
		end
		LastValue = Characters[j] + 1
	end

	if j > 0 then
		Characters[j] = LastValue
	end

	return setmetatable(Characters, BigNum)
end

local function IsNegative(self: BigNum, Base: number)
	return self[1] >= Base / 2
end

local function abs(self: BigNum, Base: number)
	local b = IsNegative(self, Base)
	return b and __unm(self, Base) or self, b
end

local function __add(a: BigNum, b: BigNum, Base: number): BigNum
	local Carry = 0

	local Characters = {}

	for i = #a, 1, -1 do
		local v = a[i] + b[i] + Carry

		if v >= Base then
			local k = v % Base
			Carry = (v - k) / Base
			v = k
		else
			Carry = 0
		end

		Characters[i] = v
	end

	return setmetatable(Characters, BigNum)
end

local function __sub(a: BigNum, b: BigNum, Base: number): BigNum
	return __add(a, __unm(b, Base), Base)
end

local function __eq(a, b)
	if #a ~= #b then --opt
		return false
	end

	for i = 1, #a do
		if a[i] ~= b[i] then
			return false
		end
	end

	return true
end

local function __lt(a: BigNum, b: BigNum, Base: number)
	local a_1 = a[1]
	local b_1 = b[1]

	if a_1 ~= b_1 then
		-- lelelels i'm keeping this
		return if a_1 >= Base / 2
			then if b_1 >= Base / 2 then a_1 < b_1 else true
			elseif b_1 >= Base / 2 then false
			else a_1 < b_1
	end

	for i = 2, #a do
		local a_i = a[i]
		local b_i = b[i]

		if a_i ~= b_i then
			return a_i < b_i
		end
	end

	return false -- equal
end

local function __mul(a: BigNum, b: BigNum, Base: number): BigNum
	local n = #a
	local Characters = {}

	for i = n, 1, -1 do
		local b_i = b[i]

		if b_i == 0 then
			if not Characters[i] then
				Characters[i] = 0
			end
			continue
		end
		for j = n, 1, -1 do
			local a_j = a[j]

			local k = i + j - n

			if k <= 0 then -- TODO: Change for loops to accomodate automatically
				continue
			end
			local x = b_i * a_j + (Characters[k] or 0)
			local y = x % Base
			local z = (x - y) / Base

			Characters[k] = y

			while z > 0 and k > 1 do
				k -= 1
				x = (Characters[k] or 0) + z
				y = x % Base
				z = (x - y) / Base

				Characters[k] = y
			end
		end
	end

	return setmetatable(Characters, BigNum)
end

local function __div(N: BigNum, D: BigNum, Base: number): (BigNum, BigNum)
	-- https://youtu.be/6bpLYxk9TUQ
	local n = #N -- n-digit numbers

	local N_IsNegative, D_IsNegative

	N, N_IsNegative = abs(N, Base)
	D, D_IsNegative = abs(D, Base)

	local Q_IsNegative

	Q_IsNegative = if N_IsNegative
		then not D_IsNegative
		elseif D_IsNegative then true
		else false

	if __lt(N, D, Base) then
		return CONSTANTS[Base][n][0], N
	end

	local NumDigits
	local SingleDigit

	for i = 1, n do
		if D[i] ~= 0 then
			NumDigits = i
			SingleDigit = D[i]
			break
		end
	end

	if not NumDigits then
		error "Cannot divide by 0"
	end

	local Q
	local R = N

	repeat
		local R_Is_Negative = IsNegative(R, Base)

		if R_Is_Negative then
			R = __unm(R, Base)
		end

		local Sub_Q = setmetatable({}, BigNum)
		local Remainder = 0

		for i = 1, NumDigits do
			local x = Base * Remainder + R[i]
			Remainder = x % SingleDigit
			Sub_Q[n - NumDigits + i] = (x - Remainder) / SingleDigit
		end

		for i = 1, n - NumDigits do
			Sub_Q[i] = 0
		end

		if R_Is_Negative then
			Sub_Q = __unm(Sub_Q, Base)
		end

		Q = if Q then __add(Q, Sub_Q, Base) else Sub_Q
		R = __sub(N, __mul(D, Q, Base), Base)
	until __lt((abs(R, Base)), D, Base)

	if IsNegative(R, Base) then
		Q = __sub(Q, CONSTANTS[Base][n][1], Base)
		R = __sub(N, __mul(D, Q, Base), Base)
	end

	if Q_IsNegative then
		Q = __unm(Q, Base)
	end

	return Q, R
end

local function __idiv(a: BigNum, b: BigNum, Base: number)
	local q, _ = __div(a, b, Base)
	return q
end

local function __pow(a: BigNum, b: BigNum, Base: number)
	local n = #a

	if __eq(b, CONSTANTS[Base][n][0]) then
		return CONSTANTS[Base][n][1]
	end

	local x = __pow(a, __div(b, CONSTANTS[Base][n][2], Base), Base)

	return if b[n] % 2 == 0
		then __mul(x, x, Base)
		else __mul(a, __mul(x, x, Base), Base)
end

local function __mod(a: BigNum, b: BigNum, Base: number)
	local _, x = __div(a, b, Base)
	return x
end

local LOG_11 = math.log(11)

local function __tostring(self, Base: number)
	local n = #self
	local Negative = IsNegative(self, Base)

	-- Not all bases with a given number of places can represent the number 10
	-- Therefore, for small numbers we can simply convert to a Lua number
	-- However, for larger numbers we need to use the math functions in this library

	-- The following conditional is derived from: 10 < Base^(n - 1) - 1

	if LOG_11 / math.log(Base) + 1 < n then
		local Characters = {}
		local Ten = CONSTANTS[Base][n][10]
		local Zero = CONSTANTS[Base][n][0]

		local i = 0

		repeat
			local x
			self, x = __div(self, Ten, Base)
			i += 1
			Characters[i] = x[n]
		until __eq(self, Zero)

		if Negative and not __eq(Characters, CONSTANTS[Base][i][0]) then
			Characters[i + 1] = "-"
		end

		return table.concat(Characters):reverse()
	else
		local PlaceValue = 1
		local Sum = 0

		for i = n, 2, -1 do
			Sum += self[i] * PlaceValue
			PlaceValue = PlaceValue * Base
		end

		return tostring(Sum + (self[1] - (Negative and Base or 0)) * PlaceValue)
	end
end

local function EnsureCompatibility(Func: any, Unary: boolean)
	if Unary then
		return function(a, ...)
			local type_a = type(a)

			if type_a == "number" then
				a = BigNum.new(tostring(a))
			elseif type_a == "string" then
				a = BigNum.new(a)
			elseif type_a ~= "table" then
				error(`bad argument to #1: expected BigNum, got {typeof(a)}`)
			end

			return Func(a, DEFAULT_BASE, ...)
		end
	end
	return function(a, b)
		local type_a = type(a)

		if type_a == "string" then
			a = BigNum.new(a)
		elseif type_a == "number" then
			a = BigNum.new(tostring(a))
		elseif type_a ~= "table" then
			error(`bad argument to #1: expected BigNum, got {typeof(a)}`)
		end

		local type_b = type(b)

		if type_b == "string" then
			b = BigNum.new(b)
		elseif type_b == "number" then
			b = BigNum.new(tostring(b))
		elseif type_b ~= "table" then
			error(`bad argument to #2: expected BigNum, got {typeof(b)}`)
		end

		if #a ~= #b then
			error(
				`You cannot operate on BigNums with different radix: {#a} and {#b}`
			)
		end

		return Func(a, b, DEFAULT_BASE)
	end
end

local function GCD(m: BigNum, n: BigNum, Base: number): BigNum
	local _0 = CONSTANTS[Base][#m][0]

	while not __eq(n, _0) do
		m, n = n, __mod(m, n, Base)
	end

	return m
end

local function LCM(m: BigNum, n: BigNum, Base: number)
	local _0 = CONSTANTS[Base][#m][0]
	return if m ~= _0 and n ~= _0
		then __mul(m, n, Base) / GCD(m, n, Base)
		else _0
end

local Char_0 = string.byte "0"

local function toScientificNotation(self, Base, DigitsAfterDecimal)
	local MaxString = __tostring(self, Base)

	if #MaxString - 2 < DigitsAfterDecimal then
		return MaxString
	end

	local Arguments = {}

	for i = 1, DigitsAfterDecimal do
		Arguments[i] = string.byte(MaxString, i) - Char_0
	end

	Arguments[DigitsAfterDecimal + 1] = string.byte(
		MaxString,
		DigitsAfterDecimal + 1
	) - Char_0 + if (string.byte(MaxString, DigitsAfterDecimal + 2) - Char_0)
			> 4
		then 1
		else 0
	Arguments[DigitsAfterDecimal + 2] = #MaxString - 1

	return string.format(
		`%d.{string.rep("%d", DigitsAfterDecimal)}e%d`,
		unpack(Arguments)
	)
end

-- Unary operators
BigNum.__tostring = EnsureCompatibility(__tostring, true)
BigNum.__unm = EnsureCompatibility(__unm, true)
BigNum.__index.toScientificNotation =
	EnsureCompatibility(toScientificNotation, true)

-- Binary operators
BigNum.__add = EnsureCompatibility(__add, false)
BigNum.__sub = EnsureCompatibility(__sub, false)
BigNum.__mul = EnsureCompatibility(__mul, false)
BigNum.__div = EnsureCompatibility(__div, false)
BigNum.__idiv = EnsureCompatibility(__idiv, false)
BigNum.__pow = EnsureCompatibility(__pow, false)
BigNum.__mod = EnsureCompatibility(__mod, false)

BigNum.__lt = EnsureCompatibility(__lt, false)
BigNum.__eq = EnsureCompatibility(__eq, false)

-- Other operations
BigNum.__index.GDC = EnsureCompatibility(GCD, false)
BigNum.__index.LCM = EnsureCompatibility(LCM, false)

local function ProcessAsDecimal(
	Bytes: number,
	Negative,
	Value,
	Power: number?,
	FromBase,
	ToBase
): any
	-- @param boolean Negative Whether the number is negative
	-- @param string Value a number in the form "%d*%.?%d*"
	-- @param number Power The power of 10 by which Value should be multiplied

	if Power then -- Truncates anything that falls after a decimal point, moved by X in AeX
		Power = tonumber(Power) :: number
		local PointLocation = (string.find(Value, ".", 1, true) or 0) - 1
		local K = PointLocation + Power

		Value = string.sub(
			string.sub(Value, 1, PointLocation)
				.. string.sub(Value, PointLocation + 2),
			1,
			if K > 0 then K else 0
		)

		if Value == "" then
			Value = "0"
		end

		return __mul(
			ProcessAsDecimal(Bytes, Negative, Value, nil, FromBase, ToBase),
			__pow(
				CONSTANTS[ToBase][Bytes][10],
				CONSTANTS[ToBase][Bytes][K - #Value],
				ToBase
			),
			ToBase
		)
	end

	local self =
		{ string.byte(string.rep("0", Bytes - #Value) .. Value, 1, -1) }
	setmetatable(self, BigNum)
	local n = #self

	local Zero = CONSTANTS[FromBase][n][0]
	local Divisor = CONSTANTS[FromBase][n][ToBase]

	for i = 1, n do
		self[i] -= Char_0
	end

	local Characters = {}
	setmetatable(Characters, BigNum)
	local i = Bytes

	repeat
		local x: BigNum
		self, x = __div(self, Divisor, FromBase)
		Characters[i] = tonumber(table.concat(x))
		i -= 1
	until __eq(self, Zero)

	for j = 1, i do
		Characters[j] = 0
	end

	return setmetatable(
		Negative and __unm(Characters, ToBase) or Characters,
		BigNum
	)
end

function BigNum.new(Number: string): BigNum
	-- Parses a number, and determines whether it is a valid number
	-- If valid, it will call ProcessAsHexidecimal or ProcessAsDecimal depending
	-- on the number's format

	-- @param string Number The number to convert into base_256
	-- @return what the called Process function returns (array representing base256)

	local Type = type(Number)

	if Type ~= "string" and Number ~= "" then
		error(
			`{tostring(Number)} is not a valid input to BigNum.new, please supply a non-empty string`
		)
	end
	local n = #Number

	local _, DecimalEndPlace, Minus, Decimal, Point =
		string.find(Number, "^(%-?)(%d*(%.?)%d*)")

	if typeof(Decimal) == "string" and Decimal ~= "" and Decimal ~= "." then
		local Power =
			string.match(Number, "^[Ee]([%+%-]?%d+)$", DecimalEndPlace + 1)

		if Power or DecimalEndPlace == n then
			return ProcessAsDecimal(
				DEFAULT_RADIX,
				Minus == "-",
				if Power and Point == "" then Decimal .. "." else Decimal,
				Power,
				10,
				DEFAULT_BASE
			)
		end
	end
	error(`{Number} is not a valid Decimal value`)
end

function BigNum.fromTable(t: { number }): BigNum
	return setmetatable(t, BigNum)
end

function BigNum:GetRange(Radix: number): string
	-- Returns the range for a given integer number of Radix
	-- @returns string

	local Max = {}
	setmetatable(Max, BigNum)

	for i = 2, Radix or DEFAULT_RADIX do
		Max[i] = DEFAULT_BASE - 1
	end

	Max[1] = (DEFAULT_BASE - DEFAULT_BASE % 2) / 2 - 1
	return `+/- {toScientificNotation(Max, DEFAULT_BASE, 2)}`
end

-- The range of usable characters should be [CHAR_OFFSET, CHAR_OFFSET + 64]
local CHAR_OFFSET = 58
local _64_2 = 64 * 64
local _64_3 = _64_2 * 64

function BigNum.fromString64(String)
	-- Creates a BigNum from characters which were outputted by toString64()
	local t = {}

	for i = 1, #String / 4 do
		local v = 4 * i
		local a, b, c, d = string.byte(String, v - 3, v)
		t[i] = (a - CHAR_OFFSET) * _64_3
			+ (b - CHAR_OFFSET) * _64_2
			+ (c - CHAR_OFFSET) * 64
			+ (d - CHAR_OFFSET)
	end

	return setmetatable(t, BigNum)
end

function BigNum.__index:toString64()
	-- returns a string of characters which hold the values in the array for storage purposes

	local t = {}

	for i = 1, #self do
		local x = self[i]
		local d = x % 64
		x = (x - d) / 64
		local c = x % 64
		x = (x - c) / 64
		local b = x % 64
		x = (x - b) / 64
		local a = x % 64

		t[i] = string.char(
			a + CHAR_OFFSET,
			b + CHAR_OFFSET,
			c + CHAR_OFFSET,
			d + CHAR_OFFSET
		)
	end

	return table.concat(t)
end

function BigNum.__index:toConstantForm(l: number)
	-- l is number of numbers per row
	local t = { "bignum.fromTable {\n\t" }
	local n = #self

	for i = 1, n do
		local v = tostring(self[i])
		table.insert(t, string.rep(" ", 0) .. v)
		table.insert(t, ",")
		table.insert(t, if i % l == 0 then "\n\t" else " ")
	end

	table.remove(t)
	table.insert(t, "\n}")

	print(table.concat(t))
end

function BigNum.__index:stringify(Base)
	return `{if IsNegative(self, Base or DEFAULT_BASE) then "-" else " "}\{{table.concat(
		self,
		", "
	)}\{`
end

local Fraction = {}
Fraction.__index = {}

local function newFraction(Numerator, Denominator, Base)
	if IsNegative(Denominator, Base) then
		Numerator = __unm(Numerator, Base)
		Denominator = __unm(Denominator, Base)
	end

	return setmetatable({
		Numerator = Numerator,
		Denominator = Denominator,
	}, Fraction)
end

local function Fraction__reduce(self, Base)
	local CommonFactor = GCD(self.Numerator, self.Denominator, Base)

	self.Numerator = __div(self.Numerator, CommonFactor, Base)
	self.Denominator = __div(self.Denominator, CommonFactor, Base)

	return self
end

local function Fraction__add(a, b, Base)
	return newFraction(
		__add(
			__mul(a.Numerator, b.Denominator, Base),
			__mul(b.Numerator, a.Denominator, Base),
			Base
		),
		__mul(a.Denominator, b.Denominator, Base),
		Base
	)
end

local function Fraction__sub(a, b, Base)
	return newFraction(
		__sub(
			__mul(a.Numerator, b.Denominator, Base),
			__mul(b.Numerator, a.Denominator, Base),
			Base
		),
		__mul(a.Denominator, b.Denominator, Base),
		Base
	)
end

local function Fraction__mul(a, b, Base)
	return newFraction(
		__mul(a.Numerator, b.Numerator, Base),
		__mul(a.Denominator, b.Denominator, Base),
		Base
	)
end

local function Fraction__div(a, b, Base)
	return newFraction(
		__mul(a.Numerator, b.Denominator, Base),
		__mul(a.Denominator, b.Numerator, Base),
		Base
	)
end

local function Fraction__idiv(a, b, Base)
	return newFraction(
		__idiv(a.Numerator, b.Numerator, Base),
		__idiv(a.Denominator, b.Denominator, Base),
		Base
	)
end

local function Fraction__mod()
	error "The modulo operation is undefined for Fractions"
end

local function Fraction__pow(self, Power, Base)
	Power = __div(Power.Numerator, Power.Denominator, Base)

	if type(Power) == "number" then
		return newFraction(
			__pow(self.Numerator, Power, Base),
			__pow(self.Denominator, Power, Base),
			Base
		)
	else
		error(
			`Cannot raise {__tostring(self, Base)} to the Power of {__tostring(
				Power,
				Base
			)}`
		)
	end
end

local function Fraction__tostring(self, Base)
	return `{__tostring(self.Numerator, Base)} / {__tostring(
		self.Denominator,
		Base
	)}`
end

local function Fraction__toScientificNotation(self, Base, DigitsAfterDecimal)
	return `{toScientificNotation(self.Numerator, Base, DigitsAfterDecimal)} / {toScientificNotation(
		self.Denominator,
		Base,
		DigitsAfterDecimal
	)}`
end

local function Fraction__lt(a, b, Base)
	return __lt(
		__mul(a.Numerator, b.Denominator, Base),
		__mul(b.Numerator, a.Denominator, Base),
		Base
	)
end

local function Fraction__unm(a, Base)
	return newFraction(__unm(a.Numerator, Base), a.Denominator, Base)
end

local function Fraction__eq(a, b, Base)
	return __eq(
		__mul(a.Numerator, b.Denominator, Base),
		__mul(b.Numerator, a.Denominator, Base),
		Base
	)
end

local function EnsureFractionalCompatibility(Func: any, Unary: boolean)
	if Unary then
		return function(a, ...)
			if getmetatable(a) ~= Fraction then
				error(`bad argument to #1: expected Fraction, got {typeof(a)}`)
			end

			return Func(a, DEFAULT_BASE, ...)
		end
	end
	return function(a, b)
		if getmetatable(a) ~= Fraction then
			error(`bad argument to #1: expected Fraction, got {typeof(a)}`)
		end

		if getmetatable(b) ~= Fraction then
			error(`bad argument to #2: expected Fraction, got {typeof(b)}`)
		end

		if #a ~= #b then
			error(
				`You cannot operate on Fractions with BigNums of different sizes: {#a} and {#b}`
			)
		end

		return Func(a, b, DEFAULT_BASE)
	end
end

-- Unary operators
Fraction.__tostring = EnsureFractionalCompatibility(Fraction__tostring, true)
Fraction.__unm = EnsureFractionalCompatibility(Fraction__unm, true)
Fraction.__index.Reduce = EnsureFractionalCompatibility(Fraction__reduce, true)
Fraction.__index.toScientificNotation =
	EnsureFractionalCompatibility(Fraction__toScientificNotation, true)

-- Binary operators
Fraction.__add = EnsureFractionalCompatibility(Fraction__add, false)
Fraction.__sub = EnsureFractionalCompatibility(Fraction__sub, false)
Fraction.__mul = EnsureFractionalCompatibility(Fraction__mul, false)
Fraction.__div = EnsureFractionalCompatibility(Fraction__div, false)
Fraction.__idiv = EnsureFractionalCompatibility(Fraction__idiv, false)
Fraction.__pow = EnsureFractionalCompatibility(Fraction__pow, false)
Fraction.__mod = EnsureFractionalCompatibility(Fraction__mod, false)

Fraction.__lt = EnsureFractionalCompatibility(Fraction__lt, false)
Fraction.__eq = EnsureFractionalCompatibility(Fraction__eq, false)

BigNum.newFraction = EnsureCompatibility(newFraction, false)

return BigNum
