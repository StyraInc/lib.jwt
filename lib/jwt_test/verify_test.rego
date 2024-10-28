package lib.jwt_test

import rego.v1

import data.lib.jwt

test_verify_rs256 if {
	token := io.jwt.encode_sign({"alg": "RS256"}, {"payload": "here"}, rsa_private)

	jwt.verify(token, {"keys": [rsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_rs384 if {
	token := io.jwt.encode_sign({"alg": "RS384"}, {"payload": "here"}, rsa_private)

	jwt.verify(token, {"keys": [rsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_rs512 if {
	token := io.jwt.encode_sign({"alg": "RS512"}, {"payload": "here"}, rsa_private)

	jwt.verify(token, {"keys": [rsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_es256 if {
	token := io.jwt.encode_sign({"alg": "ES256"}, {"payload": "here"}, ecdsa_private)

	jwt.verify(token, {"keys": [ecdsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_es384 if {
	token := io.jwt.encode_sign({"alg": "ES384"}, {"payload": "here"}, ecdsa_private)

	jwt.verify(token, {"keys": [ecdsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_es512 if {
	token := io.jwt.encode_sign({"alg": "ES512"}, {"payload": "here"}, ecdsa_private)

	jwt.verify(token, {"keys": [ecdsa_public]})

	not jwt.verify(token, "wrong")
}

test_verify_ps256 if {
	token := io.jwt.encode_sign({"alg": "PS256"}, {"payload": "here"}, rsa_pss_private)

	jwt.verify(token, {"keys": [rsa_pss_public]})

	not jwt.verify(token, "wrong")
}

test_verify_ps384 if {
	token := io.jwt.encode_sign({"alg": "PS384"}, {"payload": "here"}, rsa_pss_private)

	jwt.verify(token, {"keys": [rsa_pss_public]})

	not jwt.verify(token, "wrong")
}

test_verify_ps512 if {
	token := io.jwt.encode_sign({"alg": "PS512"}, {"payload": "here"}, rsa_pss_private)

	jwt.verify(token, {"keys": [rsa_pss_public]})

	not jwt.verify(token, "wrong")
}

test_verify_all_keys_in_set if {
	token := io.jwt.encode_sign({"alg": "PS512"}, {"payload": "here"}, rsa_pss_private)

	jwt.verify(token, {"keys": [rsa_pss_public, ecdsa_public, rsa_pss_public]})

	not jwt.verify(token, "wrong")
}

test_invalid_algorithm if {
	token := sprintf("%s.%s.", [
		base64url.encode_no_pad(`{"alg": "none"}`),
		base64url.encode_no_pad(`{"payload": "here"}`),
	])

	not jwt.verify(token, {"keys": [rsa_public]})
}

test_wrong_key if {
	token := io.jwt.encode_sign({"alg": "PS512"}, {"payload": "here"}, rsa_pss_private)

	not jwt.verify(token, {"keys": [rsa_public]})
}

test_verify_hs256_not_supported if {
	token := io.jwt.encode_sign(
		{"alg": "HS256"},
		{"payload": "here"},
		{"kty": "oct", "k": base64url.encode_no_pad("supersecret")},
	)

	not jwt.verify(token, "supersecret")
}

rsa_private := {
	"kty": "RSA",
	"n": "muU3VcHLEcZqAvpkrV36oS0pPUhH8-qOumoF2JSx2l8FvkzA4m-9cFFj72qBMg1_DHeuZNMBmn3cT_wjyNl7P49jt8G6kD32uuouK2rKhPJpx2KvGC5moR5_6IbQ87S6C1WxHzuAzdbbxRFimeZUBsnM1mb2rxYJLDTsl39e0GE69eP4nfof6aJl2j6duRHtPDeDFJUgtwE3-NnKcKUzdgFxO8n4QefbOCiNrDjaganMYM4leUpnPGKpAAfsH0yjZp_tmrLFDZRzjW5iZzkY9vw6kn8O0QVZZ3-hMADJsl8sRPtkJb-sQ4bDWSr0uKwuO0SJzlxh0H7OSQdPGA18rw",
	"e": "AQAB",
	"d": "F8BBsbootRM2FTp82TfvDZYwW8_At2ObkB-1bBuHgVhkYo-VXK339TLdvovtFJY3iYYJLTeiaCSYICxQS7ohaRfHxBkGI5uva24rjIfFrF4ZdIkqwmv3Bl9NYK6EzXcZt1GOpR80JcamO1EU9qFNTXSAdCMkp1NF2SFNDVaVXMvsK_wnwJWVYdYij3OKR1v_yffzK9zKI2RHgMiDWqaIsP6V3ihQ6FKk0Lw6o7MnU8oTckTtE2QKo3-UZnksfUM9CBg2c5JD0cIiqc9pHKrcStPmk7FQYOnQvEQLd9e9_ODMfxO1nLk_fwtmnezgsF5dwQgSdS2esko4KqyN9DqcyQ",
	"p": "zV_nGl-G4etkibzYxRewiKtWV6YOF7ZfpA-5ikAmI1jmUMBZkAYMzaY2t-W2vVGYOZcaVzB2wx35ffxboQ_hvnml2YUQ_ru9XuMOJMCubNMGCLhgAqKxKfYjmXZsqKbPefUjQ3POsQGidZOLYs5PXW3tDONL0YGi_BwiyZQGu3k",
	"q": "wRPWYeq0w5oLde3eLccuoFoMLiHyd2aypgad6PFX0aHEZKNPleXjy7q8sqs1dsvxTs_-Xr5jw4Pxf6yQgWUuVVDoeFDvlfn8xcnhz8amKSPo-uI2WL9--qce_a-9cehOMhaA-3YRBepVXo5Ge1wcMzazhR-Ka84WAaVh8XZFx2c",
	"dp": "NEBsKfeX967OG4UimbKXRY5iH1auSzYpSzJ9AEGl8mRR5MWrg8smQsRBM7SMM8qosi5Rk1FPRgFAUt976JSD2NRWb-s9EbJuUc_u70beme1uoZVXSBRggs6O7CKHLrmSG_NUj3rNYZeK3-M0GWVoJ9sp7pd92MXk08PMzgCNXfE",
	"dq": "Q-wFm_akVrdHVtoyMeqDJZfn9wasNILlT_C99meInE-LNlgZNENmSpJLtZLzQPJn1nDnLE9P60TsXRzIzSxaC1tmHIVkc185JB9sF9rrM0fVuwR_V-Mt-WF3TolXXM37TDWMdGnJfUo9dAEbHGR_6yhQKQG6gUhDh5q1hOs1ivs",
	"qi": "uX1a5dff4F709z3-gvoaBeFaWqTkpcXTvUZYdawbmHwTuUpK4FM6Bi8BpbqUjZdgHiTA7czZJNgX4jGGAxkpj86lX3zCyC6hbvWrXblmCVPALlUadEKo8a2pywoN4C2lPXun_fYF4QpHDIK7DnlgLU9KzDlbPq7IpXzHqfMPA48",
}

rsa_public := {
	"kty": "RSA",
	"n": "muU3VcHLEcZqAvpkrV36oS0pPUhH8-qOumoF2JSx2l8FvkzA4m-9cFFj72qBMg1_DHeuZNMBmn3cT_wjyNl7P49jt8G6kD32uuouK2rKhPJpx2KvGC5moR5_6IbQ87S6C1WxHzuAzdbbxRFimeZUBsnM1mb2rxYJLDTsl39e0GE69eP4nfof6aJl2j6duRHtPDeDFJUgtwE3-NnKcKUzdgFxO8n4QefbOCiNrDjaganMYM4leUpnPGKpAAfsH0yjZp_tmrLFDZRzjW5iZzkY9vw6kn8O0QVZZ3-hMADJsl8sRPtkJb-sQ4bDWSr0uKwuO0SJzlxh0H7OSQdPGA18rw",
	"e": "AQAB",
}

ecdsa_private := {
	"kty": "EC",
	"crv": "P-256",
	"x": "8L-bSje3npIt-w-MpYMq2-3d6UHuRR-wPI4yoEVmTaM",
	"y": "dVO5Zag05NC-eMpZbLhzZ-ep-Kuwk28_x_Dl2qQUZm4",
	"d": "JaalM0Qmx9E0LGo3cImxbN3VXRFVx6winOJGQrMWiwM",
}

ecdsa_public := {
	"kty": "EC",
	"crv": "P-256",
	"x": "8L-bSje3npIt-w-MpYMq2-3d6UHuRR-wPI4yoEVmTaM",
	"y": "dVO5Zag05NC-eMpZbLhzZ-ep-Kuwk28_x_Dl2qQUZm4",
}

rsa_pss_private := {
	"kty": "RSA",
	"n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
	"e": "AQAB",
	"d": "KIBGrbCSW2O1yOyQW9nvDUkA5EdsS58Q7US7bvM4iWpuDIBwCXur7_VuKnhn_HUhURLzj_JNozynSChqYyG-CvL-ZLy82LUE3ZIBkSdv_vFLFt-VvvRtf1EcsmoqenkZl7aN7HD7DJeXBoz5tyVQKuH17WW0fsi9StGtCcUl-H6KzV9Gif0Kj0uLQbCg3THRvKuueBTwCTdjoP0PwaNADgSWb3hJPeLMm_yII4tIMGbOw-xd9wJRl-ZN9nkNtQMxszFGdKjedB6goYLQuP0WRZx-YtykaVJdM75bDUvsQar49Pc21Fp7UVk_CN11DX_hX3TmTJAUtqYADliVKkTbCQ",
	"p": "y1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl-zNVKP8w4eBv0vWuJJF-hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm_UZvtRpWrnBjcEVtHEJNpbU9pLD5iZ0J9sbzPU_LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0",
	"q": "yH0X-jpoqxj4efZfkUrg5GbSEhf-dZglf0tTOA5bVg8IYwtmNk_pniLG_zI7c-GlTc9BBwfMr59EzBq_eFMI7-LgXaVUsM_sS4Ry-yeK6SJx_otIMWtDfqxsLD8CPMCRvecC2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8",
	"dp": "GYSOJoeKmbZ4So2OEyg48UGLn10nSwIvb9xcZr3IQ8DoJ-C_j0VXTMAzZrNm7C9Jubj59dOBMzOsNb889c8Cs-aU6TyNDo4Fjdd06vPjyr5v-BmtjI4DoD1kJLJbpTv6DHF2z8Fgt4XEXa_bXELZ_SJn_Z9rKS_-hAxSHfh6f-0",
	"dq": "CqVZ2JexZyR0TUWf3X80YexzyzIq-OOTWicNzDQ29WLm9xtr2gZ0SUlfd72bGpQoyvDuawkm_UxfwtbIxALkvpg1gcN9s8XWrkviLyPyZF7H3tRWiQlBFEDjnZXa8I7pLkROCmdp3fp17cxTEeAI5feovfzZDH39MdWZuZrdh9E",
	"qi": "UxL_Eu5yvMK8SAt_dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5Ky18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrBjg_3747WSsf_zBTcHihTRBdAv6OmdhV4_dD5YBfLAkLrd-mX7iE",
}

rsa_pss_public := {
	"kty": "RSA",
	"n": "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwrXwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-BtOLpJofmbGEGgvmwyCI9Mw",
	"e": "AQAB",
}
