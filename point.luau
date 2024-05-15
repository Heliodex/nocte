local bigint = require "bigint"
local big = bigint.new

local point = {}
point.__index = point
setmetatable(point, { __index = bigint })

export type Point = {
	x: any,
	y: any,
}
type BigInt = any

-- fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
local p =
	big "115792089237316195423570985008687907853269984665640564039457584007908834671663"

local big0 = big(0)
local big1 = big(1)
local big2 = big(2)
local big3 = big(3)
local big7 = big(7)

-- curve equation: y^2 = x^3 + 7

function point.new(x: BigInt, y: BigInt): Point & typeof(point)
	if x == big0 or y == big0 then
		return setmetatable({ x = big0, y = big0 } :: any, point)
	end

	-- local c = (x ^ 3 + big7) % p
	-- local d = (y ^ 2) % p
	-- if c ~= d then
	-- 	error ("Invalid point: c-d=" .. tostring(c - d))
	-- end

	return setmetatable({ x = x, y = y } :: any, point)
end

local inf = point.new(big0, big0)

function point.__eq(self: Point, other: Point): boolean
	return self.x == other.x and self.y == other.y
end

function point.__tostring(self: Point): string
	return `Point({self.x}, {self.y})`
end

-- Elliptic curve point negation
function point.__unm(self: Point): Point
	return point.new(self.x, -self.y)
end

-- Addition of points refers to the usual elliptic curve group operation.
function point.__add(P: Point, Q: Point): Point
	if P == inf then
		return Q
	elseif Q == inf then
		return P
	end

	-- With 2 distinct points, P and Q, addition is defined as the negation of the point resulting from the intersection of the curve, E, and the straight line defined by the points P and Q, giving the point, R.
	local xp, yp = P.x, P.y
	local xq, yq = Q.x, Q.y

	local m = yq - yp / xq - xp
	local xr = m ^ 2 - xp - xq
	local yr = m * (xp - xr) - yp

	return point.new(xr, yr)
end

-- Where the points P and Q are coincident (at the same coordinates), addition is similar, except that there is no well-defined straight line through P, so the operation is closed using a limiting case, the tangent to the curve, E, at P.
function point.double(P: Point): Point
	if P == inf then
		return inf
	end

	local xp, yp = P.x, P.y
	local m = (big3 * xp ^ 2) / (big2 * yp)
	local xr = m ^ 2 - big2 * xp
	local yr = m * (xp - xr) - yp

	return point.new(xr, yr)
end

-- Multiplication (⋅) of an integer and a point refers to the repeated application of the group operation.
-- The straightforward way of computing a point multiplication is through repeated addition. However, there are more efficient approaches to computing the multiplication.
-- The simplest method is the double-and-add method, similar to square-and-multiply in modular exponentiation.
function point.multiply(a: BigInt, b: Point): Point
	local result = inf
	local base = b

	local iters = 0
	while a > big0 do
		iters += 1
		print(iters)
		if a % big2 == big1 then
			result += base
		end
		result = result:double()
		a /= big2
	end

	return result
end

return point
