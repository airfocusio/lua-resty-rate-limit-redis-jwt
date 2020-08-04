local _M = { _VERSION = "0.1.0" }

local reset = 0

local function expire_key(redis_connection, key, interval, log_level)
    local expire, error = redis_connection:expire(key, interval)
    if not expire then
        ngx.log(log_level, "failed to get ttl: ", error)
        return
    end
end

local function bump_request(redis_connection, redis_pool_size, key, rate, interval, current_time, log_level)
    local count, error = redis_connection:incr(key)
    if not count then
        ngx.log(log_level, "failed to incr count: ", error)
        return
    end

    if tonumber(count) == 1 then
        reset = (current_time + interval)
        expire_key(redis_connection, key, interval, log_level)
    else
        local ttl, error = redis_connection:pttl(key)
        if not ttl then
            ngx.log(log_level, "failed to get ttl: ", error)
            return
        end
        if ttl == -1 then
            ttl = interval
            expire_key(redis_connection, key, interval, log_level)
        end
        reset = (current_time + (ttl * 0.001))
    end

    local ok, error = redis_connection:set_keepalive(60000, redis_pool_size)
    if not ok then
        ngx.log(log_level, "failed to set keepalive: ", error)
    end

    local remaining = rate - count

    return { count = count, remaining = remaining, reset = reset }
end

local function extract_request_key(verifiers)
    local key = "ip:"..ngx.var.remote_addr
    local anonymous = true
    local auth_header = ngx.req.get_headers()["Authorization"]

    local ok, jwt = pcall(require, "rate_limit.jwt")
    if not ok then
        ngx.log(ngx.ERR, "failed to require jwt")
        return key, anonymous
    end

    if auth_header and auth_header:sub(1, #"Bearer ") == "Bearer " then
        local token = auth_header:sub(#"Bearer " + 1)
        local parsed = jwt:load_jwt(token)
        if parsed then
            local verified = jwt:verify(function(id) return verifiers[id] end, token)
            if verified and verified["verified"] then
                key = "jwt:"..verified["payload"]["sub"]
                anonymous = false
            end
        end
    end

    return key, anonymous
end

function _M.limit(config)
    local enforce_limit = true
    if config.includes and #config.includes > 0 then
        enforce_limit = false
        for idx = 1, #config.includes do
            local pattern = config.includes[idx]
            if string.match(ngx.var.request_uri, pattern) then
                enforce_limit = true
            end
        end
    end
    if config.excludes and #config.excludes > 0 then
        for idx = 1, #config.excludes do
            local pattern = config.excludes[idx]
            if string.match(ngx.var.request_uri, pattern) then
                enforce_limit = false
            end
        end
    end

    if enforce_limit then
        local log_level = config.log_level or ngx.NOTICE

        if not config.connection then
            local ok, redis = pcall(require, "rate_limit.redis")
            if not ok then
                ngx.log(ngx.ERR, "failed to require redis")
                return
            end

            local redis_config = config.redis_config or {}
            redis_config.timeout = redis_config.timeout or 1
            redis_config.host = redis_config.host or "127.0.0.1"
            redis_config.port = redis_config.port or 6379
            redis_config.pool_size = redis_config.pool_size or 100

            local redis_connection = redis:new()
            redis_connection:set_timeout(redis_config.timeout * 1000)

            local redis_connection_opts = {}
            redis_connection_opts.ssl = redis_config.ssl or false
            redis_connection_opts.ssl_verify = redis_config.ssl_verify or false
            redis_connection_opts.server_name = redis_config.host
            local ok, error = redis_connection:connect(redis_config.host, redis_config.port, redis_connection_opts)
            if not ok then
                ngx.log(log_level, "failed to connect to redis: ", error)
                return
            end

            if redis_config.password then
                local res, error = redis_connection:auth(redis_config.password)
                if not res then
                    ngx.log(log_level, "failed to connect to redis: ", error)
                    return
                end
            end

            config.redis_config = redis_config
            config.connection = redis_connection
        end

        local current_time = ngx.now()
        local connection = config.connection
        local redis_pool_size = config.redis_config.pool_size
        local ok, key, anonymous = pcall(extract_request_key, config.jwt_verifiers)
        local rate = 1
        if ok and not anonymous then
            rate = config.rate or 10
        else
            rate = config.rate_anonymous or 1
        end
        local interval = config.interval or 1

        local response, error = bump_request(connection, redis_pool_size, key, rate, interval, current_time, log_level)
        if not response then
            return
        end

        if response.count > rate then
            local retry_after = math.floor(response.reset - current_time)
            if retry_after < 0 then
                retry_after = 0
            end

            ngx.header["Content-Type"] = "application/json; charset=utf-8"
            ngx.header["X-RateLimit-Limit"] = rate
            ngx.header["X-RateLimit-Remaining"] = 0
            ngx.header["X-RateLimit-Reset"] = math.floor(response.reset)
            ngx.header["Retry-After"] = retry_after
            ngx.status = 429
            ngx.say('{"message":"Your request count ' .. response.count .. ' is over the allowed limit of ' .. rate .. '."}')
            ngx.exit(ngx.HTTP_OK)
        else
            ngx.header["X-RateLimit-Limit"] = rate
            ngx.header["X-RateLimit-Remaining"] = math.floor(response.remaining)
            ngx.header["X-RateLimit-Reset"] = math.floor(response.reset)
        end
    else
        return
    end
end

return _M
