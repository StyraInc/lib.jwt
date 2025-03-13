package example.app_test

import data.example.app

test_allow_valid_jwt if {
	decision := app.decision with input.token as token
		with data.lib.config.jwt as {
			"allowed_issuers": [
				"https://issuer1.example.com",
				"https://issuer2.example.com",
			],
			"jwks": {"keys": [{
				"kty": "RSA",
				"n": "0uUZ4XpiWu4ds6SxR-5xH6Lxu45mwgw6FDfZVZ-vGu1tsuZaUgdrJ-smKVX4L7Qa_q2pKPPepKnWhlktwXYNIk1ILkWSMLCBBzTWgulh5TTl3WCPjpzLKS4ZX0uoCt3wylIozzDIajGpSLve_xQ6G56FtZwlUC1lMPRBOV3ULOXAP24u5fwmWE6kX_rj6VW7Q4FpWo5kIQsNIukGzX6JznbxgX9NDWXpXgD8-MhnLIWtfPFK5S-BFoQGk4fXyuOVTcWFecwlh9SPbeCSQrVv1GnXFdGW1lFljK9QIhXWK38D7mdD279jrw9UW065ktnfZ4VxjjPa2COAzYEA85eRZQ",
				"e": "AQAB",
			}]},
			"input_path_jwt": "input.token",
		}

	decision.allow
}

token := io.jwt.encode_sign(
	{"typ": "JWT", "alg": "RS512"},
	{
		"exp": 2730277802,
		"iss": "https://issuer1.example.com",
		"user": {"roles": ["admin"]},
	},
	rsa_private_key,
)

rsa_private_key := {
	"kty": "RSA",
	"n": "0uUZ4XpiWu4ds6SxR-5xH6Lxu45mwgw6FDfZVZ-vGu1tsuZaUgdrJ-smKVX4L7Qa_q2pKPPepKnWhlktwXYNIk1ILkWSMLCBBzTWgulh5TTl3WCPjpzLKS4ZX0uoCt3wylIozzDIajGpSLve_xQ6G56FtZwlUC1lMPRBOV3ULOXAP24u5fwmWE6kX_rj6VW7Q4FpWo5kIQsNIukGzX6JznbxgX9NDWXpXgD8-MhnLIWtfPFK5S-BFoQGk4fXyuOVTcWFecwlh9SPbeCSQrVv1GnXFdGW1lFljK9QIhXWK38D7mdD279jrw9UW065ktnfZ4VxjjPa2COAzYEA85eRZQ",
	"e": "AQAB",
	"d": "uz-vbjbu6gC0-BjCgmhNCLBXvklkwEy0d9i4OQFCXoykJrPG5HSxyXLmVZoY3EInT197UpRoM_7-lBeaO96uyqxtHXVBpJMSydM51mjHz6FBqjPFQsD0bk8ABOl0l2Sq5vildoQmoVZ2qwQkFIqUQIsyxo0qLblT0qNy35Yi5uvhKLEFvYUIpbO92Hh_fL-boXwGCIlfGEE5ipkNYoWMOwgSOwqdR3DnqKKjcZdw31hhTGNrdXFtT0_MTigXujo6uyy5JO13ylmy_OZGKOhNeuHiY4yDhYe2m6RhmGDfKjob5A3Z0rPKtLhV5k0NeK17kRBVIUXNh4si0v_IhLdR",
	"p": "7ZSHQiR5lRitPWCywF9uGwUlx4GvE2hIEQX1pTK66abRwFVoXqRUUrg9pqlpVa7tpC13PFrrK7qvdFivXAR0eO4PU1IsUv-ls1M9zckNhELaoZTjc65xkS7qfJ3dZP98FXzGX-HN_WDpHLO0kF_CZHNY8BM6qeRVmtrBrNIXsu0",
	"q": "4z7tBxMd6JJCBS8FhwkB_GU4_qGeGWMF-cCSTeoVIWQmJboY6GsImKzQLgNtY6LGt5tsLuxoDVSw-O0SYDMYjLWHSDVOt7TgCG-Ow0g7109aFubR3XkkJ43pGqeEnWKjAMgqz53eAtjHc6mWnFW_HsaB_X04VnRfHNVsw9YnMVk",
	"dp": "OXzBJd4RlWQ9NybY2fe9eshKFfZpWLbZCVV51RlrZPI6uuFvucblqIZwVI2VsWf8lMdznKUbVp97qRl0hT2GuWRRTQYLN6IohDXWNJ87qA9NO9_9EZbaYBkMIE9KrQ-tBL4Gelj3MSJsBcfuHyksroXCtYTRox5fIHNifeDwXxk",
	"dq": "edF1xuEcm1wsQBMg526QvfiVQQrqcbl_ro7o3xOpGClTuc21JIKcLRwWzVPRBCRyWmLa75yTevH3nLmZrDA37NYzGyZYeGph3qPO6CiEy7siFDzQK-WQ2BNe7ob2tFf4AadMK9f495W19e7nag8dUSYg8P57gP0JL6_JioH2qKE",
	"qi": "KDnZhZDBamNtT-quKAVQJJf2X8OR-pqCOCeps3Aya5VukO6kf90JD1z36xo6m4v7jj8FMeC6u4WbLIzAIK7LLSTEhHtdHac_9UaUh_D37uMhm97YQQsT8hthbDtaqad2jGFETZmxb1TOtsrPxRESVxYkHvZcuyw2CMH8bDWKbBA",
}
