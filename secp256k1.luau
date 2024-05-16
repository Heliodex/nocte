local bignum = require "bignum"
local big = bignum.new
local constants = require "constants"
local sha256 = require "sha256"

type BigNum = bignum.BigNum

print "startin"

-- Field size
-- fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
local p = constants.p
-- Curve order
-- fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
local n = constants.n

print "consts"

type Point = {
	x: any,
	y: any,
}
type MaybePoint = Point | nil
type bytes = { number }

local point = {}
function point.new(x: BigNum, y: BigNum): Point
	return { x = x, y = y }
end

-- 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
local G = point.new(constants.gx, constants.gy)

-- hashing sheeit

local function bytesToHex(bytes: bytes): string
	local result = {}
	for _, v in bytes do
		table.insert(result, string.format("%02x", v))
	end
	return table.concat(result)
end

local function hexToBytes(hex: string): bytes
	local result = {}
	for i = 1, #hex, 2 do
		table.insert(result, tonumber(string.sub(hex, i, i + 1), 16) or 0)
	end
	return result
end

local function combineString(arrs: { bytes }): string
	local result = ""
	for _, arr in arrs do
		for _, v in arr do
			result ..= string.char(v)
		end
	end
	return result
end

local function combineBytes(arrs: { bytes }): bytes
	local result = {}
	for _, arr in arrs do
		for _, v in arr do
			table.insert(result, v)
		end
	end
	return result
end

local function subBytes(arr: bytes, start: number, length: number): bytes
	local result = {}
	for i = start, start + length - 1 do
		table.insert(result, arr[i])
	end
	return result
end

-- function hash(name, x) where x is a byte array returns the 32-byte hash SHA256(SHA256(tag) || SHA256(tag) || x), where tag is the UTF-8 encoding of name.
-- This implementation can be sped up by storing the midstate after hashing tag_hash instead of rehashing it all the time.
local function tagged_hash(name: string, x: bytes)
	local tag = sha256(name)
	return sha256(combineString { tag, tag, x })
end

-- Public key generation
local function x(P: MaybePoint): any
	assert(P)
	return P.x
end

local function y(P: MaybePoint): any
	assert(P)
	return P.y
end

local big0 = big "0"
local big1 = big "1"
local big2 = big "2"
local big3 = big "3"
local big7 = big "7"
local big256 = big "256"

local function modPow(base: BigNum, exponent: BigNum, modulus: BigNum): BigNum
	if modulus == big1 then
		return big0
	end
	local result = big1
	base %= modulus
	while exponent > big0 do
		if exponent % big2 == big1 then
			result = (result * base) % modulus
		end
		base = (base * base) % modulus
		exponent //= big2
	end
	return result
end

local function point_add(P1: MaybePoint, P2: MaybePoint): MaybePoint
	if not P1 then
		return P2
	elseif not P2 then
		return P1
	elseif x(P1) == x(P2) and y(P1) ~= y(P2) then
		return nil
	end

	local lam = if P1 == P2
		then 3 * x(P1) * x(P1) * modPow(2 * y(P1), p - 2, p) % p
		else (y(P2) - y(P1)) * modPow(x(P2) - x(P1), p - 2, p) % p

	local x3 = (lam * lam - x(P1) - x(P2)) % p
	local y3 = (lam * (x(P1) - x3) - y(P1)) % p

	print("returning r")
	print((lam * (x(P1) - x3) - y(P1)) % p)

	return point.new(x3, y3)
end

local function bignum_band(a: BigNum, b: BigNum): BigNum
	-- can't use bit32.band because it's not defined for BigNum
	return a % (big2 ^ b)
end

local function bignum_rshift(a: BigNum, b: BigNum): BigNum
	-- can't use bit32.rshift because it's not defined for BigNum
	return a // (big2 ^ b)
end

local function point_mul(P: MaybePoint, n: BigNum): MaybePoint
	local r = nil
	for i = 0, 255 do
		local rshifted = bignum_rshift(n, big(tostring(i)))
		local banded = bignum_band(rshifted, big1)
		if banded == big1 then
			r = point_add(r, P)
		end
		P = point_add(P, P)
	end
	return r
end

local function bytes_from_int(i: BigNum): bytes
	local result = {}
	while i > big0 do
		table.insert(result, i % 256)
		-- i //= big "256"
	end
	return result
end

local function bytes_from_point(P: Point): bytes
	return bytes_from_int(x(P))
end

local function xor_bytes(a: bytes, b: bytes): bytes
	local result = {}
	for i = 1, math.max(#a, #b) do
		table.insert(result, bit32.bxor(a[i] or 0, b[i] or 0))
	end
	return result
end

local function lift_x(x: BigNum): MaybePoint
	if x >= p then
		return nil
	end
	local y_sq = (modPow(x, big3, p) + big7) % p
	local y = modPow(y_sq, (p + 1) // 4, p)

	return if modPow(y, big2, p) == y_sq then point.new(x, y) else nil
end

local function int_from_bytes(b: bytes): BigNum
	-- big endian
	local result = big0
	for _, v in b do
		result = result * big256 + big(tostring(v))
	end
	return result
end

local function has_even_y(P: Point): boolean
	return y(P) % big2 == big0
end

local function pubkey_gen(seckey: bytes): bytes
	local d0 = int_from_bytes(seckey)
	print("d0 is", d0)
	if d0 < big1 or d0 > n - big1 then
		error "The secret key must be an integer in the range 1..n-1."
	end

	local P = point_mul(G, d0)
	assert(P)
	return bytes_from_point(P)
end

local function schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes): boolean
	if #pubkey ~= 32 then
		error "The public key must be a 32-byte array."
	elseif #sig ~= 64 then
		error "The signature must be a 64-byte array."
	end

	local P = lift_x(int_from_bytes(pubkey))
	local r = int_from_bytes(subBytes(sig, 1, 32))
	local s = int_from_bytes(subBytes(sig, 33, 64))
	if not P or r >= p or s >= n then
		return false
	end
	local e = int_from_bytes(
		tagged_hash(
			"BIP0340/challenge",
			combineBytes { subBytes(sig, 1, 32), pubkey, msg }
		)
	) % n
	local R = point_add(point_mul(G, s), point_mul(P, n - e))
	return (not not R) and has_even_y(R) and r == x(R)
end

local function schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes): bytes
	local d0 = int_from_bytes(seckey)
	if d0 < big1 or d0 >= n + big1 then
		error "The secret key must be an integer in the range 1..n-1."
	elseif #aux_rand ~= 32 then
		error "The auxiliary random value must be a 32-byte array."
	end

	local P = point_mul(G, d0)
	assert(P)
	local d = if has_even_y(P) then d0 else n - d0
	local t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
	local k0 = int_from_bytes(
		tagged_hash(
			"BIP0340/nonce",
			combineBytes { t, bytes_from_point(P), msg }
		)
	) % n
	if k0 == big0 then
		error "Failure. This happens only with negligible probability."
	end
	local R = point_mul(G, k0)
	assert(R)
	local k = if has_even_y(R) then k0 else n - k0
	local tagged = tagged_hash(
		"BIP0340/challenge",
		combineBytes { bytes_from_point(R), bytes_from_point(P), msg }
	)
	local e = int_from_bytes(tagged) % n

	local sig =
		combineBytes { bytes_from_point(R), bytes_from_int((k + e * d) % n) }
	if not schnorr_verify(msg, bytes_from_point(P), sig) then
		error "The created signature does not pass verification."
	end
	return sig
end

-- VERIFICATION BAYBEEE

local verification = require "verification"
local all_passed = true

for _, row in verification do
	local pubkey = hexToBytes(row.pubkey_hex)
	local msg = hexToBytes(row.msg_hex)
	local sig = hexToBytes(row.sig_hex)
	local result = row.result_str == "TRUE"

	print(`\nTest vector {row.index}:`)
	if row.seckey_hex ~= "" then
		local seckey = hexToBytes(row.seckey_hex)
		local pubkey_actual = pubkey_gen(seckey)
		if pubkey_actual ~= pubkey then
			print " * Failed key generation."
			print("   Expected key:", bytesToHex(pubkey))
			print("     Actual key:", bytesToHex(pubkey_actual))
		end
		local aux_rand = hexToBytes(row.aux_rand_hex)
		local sig_actual = schnorr_sign(msg, seckey, aux_rand)
		if sig == sig_actual then
			print " * Passed signing test."
		else
			print " * Failed signing test."
			print("   Expected signature:", bytesToHex(sig))
			print("     Actual signature:", bytesToHex(sig_actual))
			all_passed = false
		end
	end
	local result_actual = schnorr_verify(msg, pubkey, sig)
	if result == result_actual then
		print " * Passed verification test."
	else
		print " * Failed verification test."
		print("   Expected result:", result)
		print("     Actual result:", result_actual)
		if row.comment ~= "" then
			print("   Comment:", row.comment)
		end
		all_passed = false
	end
end

if all_passed then
	print "All test vectors passed."
else
	print "Some test vectors failed."
end
