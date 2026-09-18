# Test fixtures

`github_app_pkcs8.pem` and `github_app_pkcs1.pem` are the same throwaway
RSA-2048 private key in PKCS#8 and PKCS#1 PEM envelopes, generated with

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out github_app_pkcs8.pem
openssl rsa -in github_app_pkcs8.pem -traditional -out github_app_pkcs1.pem
```

They exist only so `github_app` unit tests can exercise PEM decoding for
both envelope tags GitHub Apps produce. They are test-only keys — they
secure nothing and must never be used as real credentials.
