# Testing

To create JWKs from PEMs, [jwker](https://github.com/jphastings/jwker) is a useful tool.

### Keys

#### Generate RSA keys

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
jwker public.pem public.jwk
jwker private.pem private.jwk
```

#### Generate ECDSA keys

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
jwker public.pem public.jwk
jwker private.pem private.jwk
```