local net = require "@lune/net"

net.serve(3223, {
	handleRequest = function(request)
		local wsKey = request.headers["sec-websocket-key"]

		print(wsKey)

		-- upgrade to websocket
		return {
			status = 101,
			headers = {
				upgrade = "HTTP/2",
				connection = "Upgrade",
			},
			body = "Hello, world!",
		}
	end,
})

print "we serving"
