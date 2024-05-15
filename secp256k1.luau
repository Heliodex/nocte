local bigint = require "bigint"
local big = bigint.new
local sha256 = require "sha256"
local point = require "point"

-- Field size
-- fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
local p =
	big "115792089237316195423570985008687907853269984665640564039457584007908834671663"
-- Curve order
-- fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
local n =
	big "115792089237316195423570985008687907852837564279074904382605163141518161494337"

local G = point.new(
	-- 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
	big "55066263022277343669578718895168534326250603453777594175500187360389116729240",
	-- 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
	big "32670510020758816978083085130507043184471273380659243275938904335757337482424"
)

local big0 = big(0)
local big1 = big(1)
local big7 = big(7)
local big256 = big(256)

-- The function bytes(x), where x is an integer, returns the 32-byte encoding of x, most significant byte first.
-- The function bytes(P), where P is a point, returns bytes(x(P)).
local function bytes(x: point.Point): { number }
	if x.x then
		x = x.x
	end

	local result = {}
	for i = 1, 32 do
		table.insert(result, (x % big256):tonumber())
		x /= big256
	end

	return result
end

-- The function int(x), where x is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is x.
local function int(x: { number }): number
	local result = 0
	for i = 1, 32 do
		result = result * 256 + x[33 - i]
	end
	return result
end

-- The function has_even_y(P), where P is a point for which not is_infinite(P), returns y(P) mod 2 = 0.
local function has_even_y(P: point.Point): boolean
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
local function lift_x(x: any): point.Point
	if x >= p then
		error "x >= p"
	end

	local c = (x ^ 3 + big7) % p
	local y = (c ^ ((p + big1) / 4)) % p
	if c ~= (y ^ 2) % p then
		error "c ≠ y^2 mod p"
	end

	if y % 2 == 0 then
		return point.new(x, y)
	else
		return point.new(x, p - y)
	end
end

local function bytesToHex(bytes: { number }): string
	local result = {}
	for _, v in bytes do
		table.insert(result, string.format("%02x", v))
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
local function hash(name: string, x: { number })
	local tag = sha256(name)
	return sha256(combineString { tag, tag, x })
end

print(bytesToHex(hash("BIP0340/nonce", stringToBytes "world")))
print(bytesToHex(hash("SampleTagName", stringToBytes "Input data")))

-- Public key generation

math.randomseed(1)

local function SecKey(): { number }
	local sk = {}
	for i = 1, 32 do
		table.insert(sk, math.random(0, 255))
	end
	return sk
end

-- The algorithm PubKey(sk) is defined as:
-- Let d' = int(sk).
-- Fail if d' = 0 or d' ≥ n.
-- Return bytes(d'⋅G).
local function PubKey(sk: { number }): { number }
	local d = big(int(sk)) :: any
	if d == big0 or d >= n then
		error "d' = 0 or d' ≥ n"
	end
	print(point.multiply(d, G))
	return bytes(point.multiply(d, G))
end

-- The secret key sk: a 32-byte array, freshly generated uniformly at random
local sk = SecKey()
local pk = PubKey(sk)
print(bytesToHex(sk))
print(bytesToHex(pk))
