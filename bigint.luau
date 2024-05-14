-- https://github.com/TeckyDemon/lua-bigint/blob/master/bigint.lua
-- Very very not fast but it actually works, unlike than my custom one

local bigint = {}
bigint.__index = bigint

type BigInt = typeof(setmetatable({}, bigint))

function bigint.new(str: string | number | BigInt)
	if getmetatable(str :: BigInt) == bigint then
		return str :: BigInt
	end
	local self = setmetatable({}, bigint)
	self.digits = {}
	for digit in string.gmatch(tostring(str), "[0-9]") do
		table.insert(self.digits, tonumber(digit))
	end
	self.signed = string.sub(tostring(str), 1, 1) == "-"
	return self
end

local big0 = bigint.new(0)
local big1 = bigint.new(1)

function bigint.clone(self)
	return bigint.new(tostring(self))
end

function bigint:__tostring()
	return (if self.signed then "-" else "") .. table.concat(self.digits)
end

function bigint:__len()
	return #self.digits
end

function bigint:__unm()
	local result = self:clone()
	result.signed = not result.signed
	return result
end

function bigint.__add(a, b): BigInt
	if getmetatable(a) ~= bigint or getmetatable(b) ~= bigint then
		return bigint.new(a) + bigint.new(b)
	end
	if a.signed and b.signed then
		return -(-a + -b)
	elseif a.signed or b.signed then
		return -(a:abs() - b:abs())
	end
	local result = {}
	local carry = 0
	local alen, blen = #a, #b
	local max_digits = math.max(alen, blen)
	for i = 0, max_digits - 1 do
		local d = ((a.digits :: { number })[alen - i] or 0)
			+ ((b.digits :: { number })[blen - i] or 0)
			+ carry
		carry = if d > 9 then 1 else 0
		result[max_digits - i] = d % 10
	end
	return bigint.new((if carry == 1 then 1 else "") .. table.concat(result))
end

function bigint.__sub(a, b): BigInt
	if getmetatable(a) ~= bigint or getmetatable(b) ~= bigint then
		return bigint.new(a) - bigint.new(b)
	end
	if a < b then
		return -(b - a)
	elseif a.signed and b.signed then
		return -b - -a
	elseif a.signed or b.signed then
		return a:abs() + b:abs()
	end
	local result = {}
	local borrow = 0
	local alen, blen = #a, #b

	for i = 0, alen - 1 do
		result[alen - i] = (a.digits[alen - i] or 0)
			- (b.digits[blen - i] or 0)
			- borrow
		borrow = (result[alen - i] < 0 and 1 or 0)
		result[alen - i] += if borrow == 1 then 10 else 0
	end
	while #result > 1 and result[1] == 0 do
		table.remove(result, 1)
	end
	return bigint.new(table.concat(result))
end

function bigint.__mul(a, b): BigInt
	if getmetatable(a) ~= bigint or getmetatable(b) ~= bigint then
		return bigint.new(a) * bigint.new(b)
	end
	if a == big0 or b == big0 then
		return big0
	elseif a.signed and b.signed then
		return -a * -b
	elseif a.signed or b.signed then
		return -(a:abs() * b:abs())
	end
	local result = big0
	local alen, blen = #a, #b

	for i = 0, alen - 1 do
		local carry = 0
		local product: { number } = {}
		for j = 0, blen - 1 do
			local p = (a.digits[alen - i] or 0) * (b.digits[blen - j] or 0)
				+ carry
			carry = p // 10
			product[blen - j] = p % 10
		end
		for k = 1, i do
			table.insert(product, 0)
		end
		result += (if carry > 0 then carry else "") .. table.concat(product)
	end
	return result
end

function bigint.__div(a, b)
	if getmetatable(a) ~= bigint or getmetatable(b) ~= bigint then
		return bigint.new(a) / bigint.new(b)
	end
	if a == big0 or b == big0 or a < b then
		return big0
	elseif a.signed and b.signed then
		return -a / -b
	elseif a.signed or b.signed then
		return -(a:abs() / b:abs())
	end
	local result: { number } = {}
	local dividend = bigint.new(a.digits[1])
	while dividend <= b do
		table.insert(dividend.digits, a.digits[#dividend + 1])
	end
	local digit = #dividend
	for i = 1, #a - digit + 1 do
		result[i] = b + if b <= dividend then 1 else 0
		while (result[i] + 1) * b <= dividend do
			result[i] += 1
		end
		dividend -= (b * result[i])
		dividend.digits[#dividend + (if dividend == big0 then 0 else 1)] =
			a.digits[digit + i]
	end
	return bigint.new(table.concat(result))
end

function bigint.__pow(a, b: number)
	if b == 0 then
		return big1
	elseif b == 1 then
		return a
	end

	local result = a
	for i = 2, b do
		result *= a
	end
	return result
end

function bigint.__mod(a, b)
	if a.signed and b.signed then
		return -a % -b
	elseif a.signed or b.signed then
		return a:abs() % b:abs()
	end
	local dividend = bigint.new(a.digits[1])
	while dividend <= b do
		table.insert(dividend.digits, a.digits[#dividend + 1])
	end
	local digit = #dividend
	for i = 1, #a - digit + 1 do
		while b <= dividend do
			dividend -= b
		end
		table.insert(dividend.digits, a.digits[digit + i])
	end
	return dividend
end

function bigint.__eq(a, b)
	if a.signed and b.signed then
		return -a == -b
	elseif a.signed or b.signed then
		return false
	end
	local alen, blen = #a, #b
	if alen ~= blen then
		return false
	end
	for i = 1, alen do
		if a.digits[i] ~= b.digits[i] then
			return false
		end
	end
	return true
end

function bigint.__lt(a, b)
	if a.signed and b.signed then
		return -a > -b
	elseif a.signed or b.signed then
		return a:abs() > b:abs()
	end
	local alen, blen = #a, #b
	if alen < blen then
		return true
	elseif alen > blen then
		return false
	end
	for i = 1, alen do
		local ad, bd = a.digits[i], b.digits[i]
		if ad < bd then
			return true
		elseif ad > bd then
			return false
		end
	end
	return false
end

function bigint.abs(self: BigInt): BigInt
	print "abs()"
	return if self.signed then -self else self
end

function bigint.tonumber(self: BigInt): number
	print "tonumber()"
	local result = 0
	for i = 1, #self do
		result += self.digits[i] * 10 ^ (#self - i)
	end
	return result
end

return bigint
