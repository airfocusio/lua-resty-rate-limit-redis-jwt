# lua-resty-rate-limit-redis-jwt

This lua scripts provide rate limiting for your kubernetes nginx-ingress by:

* Using the provided JWT subject to identify the user, or
* fallback to use the IP to identify the user.

To share the request counter between multiple nginx instances a redis is used.

## Kubernetes

```yaml
# nginx-ingress-values.yaml
controller:
  config:
    location-snippet: |
      access_by_lua '
        local ok, limit = pcall(require, "rate_limit.limit")
        if not ok then
          ngx.log(ngx.ERR, limit)
          return
        end
        local ok, ret = pcall(limit.limit, {
          rate = 600,
          rate_anonymous = 60,
          interval = 60,
          log_level = ngx.ERR,
          redis_config = {
            host = "redis",
            port = 6379,
            ssl = true,
            password = "password",
            timeout = 1,
            pool_size = 100
          },
          includes = {
            "^/api/"
          },
          excludes = {
            "^/api/auth/oauth"
          },
          jwt_verifiers = {
            ["1"] = "EyllPgDqUmu9T+ununAWNL02fKXjQfo+QWQNpqDU6TA=",
            ["2"] = [[-----BEGIN PUBLIC KEY-----
                      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuiq3ip9hokrXtxPKEaN
                      JXmBqZuPt0pNINdGe8f87Yc0lgr4QMwOEQSfRKOnZZFGMdqEvIWR/8fTiOVW2oMr
                      MeudgxmdHECHQmLRAxacNTjLT8gKdhIgAzmqKSSLg4pDchg2J7M7T4KHODtcEY+t
                      MY9bpi2CCRndnoPp6ieUFRk+eEaABEdTb/4tFqHEkg4QCv/UUoWEgiKCpL02AqE9
                      c1iDf6KRgeQFEJUQGCu+RTiCqbIel8mTQoNY9zS/A4pPZ+7fsNEhFfF8FzcbuUd+
                      FezxxjscLyDwvo2892A0Vh8F/Yf5z/hgRXiPUu9yycwSM01MlknU6SAoWumrl3VZ
                      BwIDAQAB
                      -----END PUBLIC KEY-----]],
            ["3"] = [[-----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE3jFoUF28hp03kO7mOxyS6Y/FYo4K
                      zkULzGv3f8S9riY3EeUkoTKSUFR7Q9RClea/dgS9pKCFqU6UkFjfAeqx1Q==
                      -----END PUBLIC KEY-----]]
          }
        })
        if not ok then
          ngx.log(ngx.ERR, ret)
          return
        end
      ';
  extraVolumes:
    - name: rate-limit-scripts
      configMap:
        name: lua-rate-limit-scripts
  extraVolumeMounts:
    - name: rate-limit-scripts-scripts
      mountPath: '/etc/nginx/lua/rate_limit
```

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: lua-rate-limit
data:
  evp.lua: "..."
  hmac.lua: "..."
  jwt.lua: "..."
  limit.lua: "..."
  redis.lua: "..."
```

## Development

If you have docker and docker-compose installed, then just run `make test` to run the test suite.
