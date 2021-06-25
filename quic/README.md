server:
	--certificate str
	--private-key str
	--port int
	--fiat-log str: log file
	--preprocess int: either 0 (receive pre-processed data) or 1 (receive raw data)
	--zero-rtt: if using zero rtt

client:
	--certificate str
	--private-key str
	--host str
	--port int
	--fiat-log str: log file
	--preprocess int: either 0 (send pre-processed data) or 1 (send raw data)
	--zero-rtt: if using zero rtt
