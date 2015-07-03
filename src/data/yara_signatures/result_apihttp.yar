rule HTTPApiFunctions {
	meta:
		description = "Uses the HTTP protocol functions"
	strings:
		$api1 = "HttpSendRequest" nocase
		$api2 = "HttpSendRequestEx" nocase
		$api3 = "HttpQueryInfo" nocase
		$api4 = "HttpAddRequestHeaders" nocase
		$api5 = "HttpEndRequest" nocase
		$api6 = "HttpOpenRequest" nocase
	condition:
    	any of them
}