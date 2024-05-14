local bigint = require "bigint"
local big = bigint.new
local sha256 = require "sha256"

-- Field size
-- fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
local CONST_P =
	big "115792089237316195423570985008687907853269984665640564039457584007908834671663"
-- Curve order
-- fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
local CONST_N =
	big "115792089237316195423570985008687907852837564279074904382605163141518161494337"

local point = {}
point.__index = point
setmetatable(point, { __index = bigint })

type Point = {
	x: any,
	y: any,
}

local big1 = big(1)
local big7 = big(7)

-- curve equation: y^2 = x^3 + 7

function point.new(x: any, y: any): Point & typeof(point)
	if x == big(0) and y == big(0) then
		return setmetatable({ x = x, y = y } :: any, point)
	end

	-- print "Calculating y^2"
	-- local left = ((y :: any) ^ 2) % CONST_P
	-- print(left)
	-- local right = ((x :: any) ^ 3 + big7) % CONST_P
	-- print(left == right)

	return setmetatable({ x = x, y = y } :: any, point)
end

function point.__eq(self: Point, other: Point): boolean
	return self.x == other.x and self.y == other.y
end

function point.__tostring(self: Point): string
	return `Point({self.x}, {self.y})`
end

local CONST_G = point.new(
	-- 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	big "55066263022277343669578718895168534326250603453777594175500187360389116729240",
	-- 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
	big "32670510020758816978083085130507043184471273380659243275938904335757337482424"
)

-- The function bytes(x), where x is an integer, returns the 32-byte encoding of x, most significant byte first.
-- The function bytes(P), where P is a point, returns bytes(x(P)).
local function bytes(x: any): string
	if x.x then
		x = x.x
	end

	local result = {}
	for i = 1, 32 do
		table.insert(result, string.char(x % 256))
		x = math.floor(x / 256)
	end
	return table.concat(result)
end

-- The function int(x), where x is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is x.
local function int(x: string): any
	local result = 0
	for i = 1, 32 do
		result = result * 256 + string.byte(x, i)
	end
	return result
end

-- The function has_even_y(P), where P is a point for which not is_infinite(P), returns y(P) mod 2 = 0.
local function has_even_y(P: Point): boolean
	return P.y % 2 == 0
end

--[[
The function lift_x(x), where x is a 256-bit unsigned integer, returns the point P for which x(P) = x[10] and has_even_y(P), or fails if x is greater than p-1 or no such point exists. The function lift_x(x) is equivalent to the following pseudocode:
	Fail if x ≥ p.
	Let c = x3 + 7 mod p.
	Let y = c^((p+1)/4) mod p.
	Fail if c ≠ y^2 mod p.
	Return the unique point P such that x(P) = x and y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
]]
local function lift_x(x: any): Point
	if x >= CONST_P then
		error "x >= p"
	end

	local c = (x ^ 3 + big7) % CONST_P
	local y = (c ^ ((CONST_P + big1) / 4)) % CONST_P
	if c ~= (y ^ 2) % CONST_P then
		error "c ≠ y^2 mod p"
	end

	if y % 2 == 0 then
		return point.new(x, y)
	else
		return point.new(x, CONST_P - y)
	end
end

local function bytesToHex(bytes: { number }): string
	local result = {}
	for i = 1, #bytes do
		table.insert(result, string.format("%02x", bytes[i]))
	end
	return table.concat(result)
end

local function stringToBytes(str: string): { number }
	local result = {}
	for i = 1, #str do
		table.insert(result, string.byte(str, i))
	end
	return result
end

local function combineString(arrs: { { number } }): string
	local result = ""
	for _, arr in arrs do
		for _, v in arr do
			result ..= string.char(v)
		end
	end
	return result
end

-- function hash(name, x) where x is a byte array returns the 32-byte hash SHA256(SHA256(tag) || SHA256(tag) || x), where tag is the UTF-8 encoding of name.
local function hash(
	name: string,
	x: string,
	cmp: string,
	cmp2: string,
	cmp3: string
)
	local tag = sha256(name)
	print("tagHash:", bytesToHex(tag))
	print("equal:\t", cmp == bytesToHex(tag))

	local tag2 = sha256(combineString { tag, tag })
	print("tagHas2:", bytesToHex(tag2))
	print("equal:\t", cmp2 == bytesToHex(tag2))

	local final = sha256(combineString { tag, tag, stringToBytes(x) })
	print("final:\t", bytesToHex(final))
	print("equal:\t", cmp3 == bytesToHex(final))

	return final
end

print()
hash(
	"BIP0340/nonce",
	"world",
	"07497734a79bcb355b9b8c7d034f121cf434d73ef72dda19870061fb52bfeb2f",
	"5301f1001a8be6253a3583927793565cef360de8bac2bdcbf37b195e699435a8",
	"46a4e03e58841a88a9f7615a02ea8ffaf3da33428ea217a7dbed2cfe2edce2d5"
)
print()
hash(
	"SampleTagName",
	"Input data",
	"b9f2df17a041758a9c947eb934da07099d64f29593b27eadf93c70875316f000",
	"caa6f7b306a33a651ced86884d2fe004fc1c20f97275bf2f0ef98b272e841fcf",
	"4c55df56134d7f37d3295850659f2e3729128c969b3386ec661feb7dfe29a99c"
)
