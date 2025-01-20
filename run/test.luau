local hash = "ee3a5eeb8a590c63f35e6b4da276ef905ebcdf2a1f2d1001b4f1f8a088d33dd9"
local pk = "ffffffffe5335006069f8b47bfface18f25e537dd4b3ec90e37d3c76a4003fce"
local sig =
	"3daea5422abb05d0bc1be1ffeb8ca97c17d6532a7c031b56077c47935cdb6cc7c56a52cede53f09b3990216f6cc26ceb0c7fea212f1821896443b4997e2d0eaa"

local v = verify(hash, pk, sig)
local s = sha256 "Hello, world!"

print(v, s)

print(ishex(hash), ishex(pk), ishex(sig))

print(json.encodestring 'Hello, "world!')
print(json.encodearray { 1, 2, 3, 4, 5 })

print "Serving on port 3223"

serve(3223, {
	request = function()
		print "Request"

		return "Hello, world!"
	end,
	websocket = function(ws)
		print("WS:", ws)
		while true do
			print(ws.next())

			ws.send "Hello, world!"
		end
	end,
})
