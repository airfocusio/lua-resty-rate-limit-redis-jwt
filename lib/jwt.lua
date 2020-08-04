-- original from https://github.com/SkyLothar/lua-resty-jwt
-- see jwt.license-original.md

local aes = require "resty.aes"
local resty_random = require "resty.random"
local cjson = require "cjson.safe"
local evp = require "rate_limit.evp"
local hmac = require "rate_limit.hmac"

local _M = { _VERSION="0.1.0" }
local mt = { __index=_M }

local string_rep = string.rep
local string_format = string.format
local string_sub = string.sub
local string_byte = string.byte
local string_char = string.char
local ngx_decode_base64 = ngx.decode_base64
local cjson_encode = cjson.encode
local cjson_decode = cjson.decode

-- define string constants to avoid string garbage collection
local str_const = {
  invalid_jwt = "invalid jwt string",
  regex_join_msg = "%s.%s",
  regex_join_delim = "([^%s]+)",
  regex_split_dot = "%.",
  regex_jwt_join_str = "%s.%s.%s",
  raw_underscore  = "raw_",
  empty = "",
  table = "table",
  plus = "+",
  equal = "=",
  dash = "-",
  underscore = "_",
  slash = "/",
  header = "header",
  payload = "payload",
  signature = "signature",
  alg = "alg",
  kid = "kid",
  exp = "exp",
  HS256 = "HS256",
  HS512 = "HS512",
  RS256 = "RS256",
  RS512 = "RS512",
  ES256 = "ES256",
  reason = "reason",
  verified = "verified",
  number = "number",
  string = "string",
  funct = "function",
  boolean = "boolean",
  table = "table",
  valid = "valid",
  internal_error = "internal error",
  everything_awesome = "everything is awesome~ :p"
}

-- @function split string
local function split_string(str, delim, maxNb)
  local result = {}
  local sep = string_format(str_const.regex_join_delim, delim)
  for m in str:gmatch(sep) do
    result[#result+1]=m
  end
  return result
end

-- @function is nil or boolean
-- @return true if param is nil or true or false; false otherwise
local function is_nil_or_boolean(arg_value)
    if arg_value == nil then
        return true
    end

    if type(arg_value) ~= str_const.boolean then
        return false
    end

    return true
end

--@function get the row part
--@param part_name
--@param jwt_obj
local function get_raw_part(part_name, jwt_obj)
  local raw_part = jwt_obj[str_const.raw_underscore .. part_name]
  if raw_part == nil then
    local part = jwt_obj[part_name]
    if part == nil then
      error({reason="missing part " .. part_name})
    end
    raw_part = _M:jwt_encode(part)
  end
  return raw_part
end


-- @function parse_jwt
-- @param encoded header
-- @param encoded
-- @param signature
-- @return jwt table
local function parse_jwt(encoded_header, encoded_payload, signature)
  local header = _M:jwt_decode(encoded_header, true)
  if not header then
    error({reason="invalid header: " .. encoded_header})
  end

  local payload = _M:jwt_decode(encoded_payload, true)
  if not payload then
    error({reason="invalid payload: " .. encoded_payload})
  end

  local basic_jwt = {
    raw_header=encoded_header,
    raw_payload=encoded_payload,
    header=header,
    payload=payload,
    signature=signature
  }
  return basic_jwt

end

-- @function parse token - this must be JWT token
-- @param token string
-- @return jwt tables
local function parse(secret, token_str)
  local tokens = split_string(token_str, str_const.regex_split_dot)
  local num_tokens = #tokens
  if num_tokens == 3 then
    return  parse_jwt(tokens[1], tokens[2], tokens[3])
  else
    error({reason=str_const.invalid_jwt})
  end
end


--@function jwt encode : it converts into base64 encoded string. if input is a table, it convets into
-- json before converting to base64 string
--@param payloaf
--@return base64 encoded payloaf
function _M.jwt_encode(self, ori)
  if type(ori) == str_const.table then
    ori = cjson_encode(ori)
  end
  return ngx.encode_base64(ori):gsub(str_const.plus, str_const.dash):gsub(str_const.slash, str_const.underscore):gsub(str_const.equal, str_const.empty)
end



--@function jwt decode : decode bas64 encoded string
function _M.jwt_decode(self, b64_str, json_decode)
  b64_str = b64_str:gsub(str_const.dash, str_const.plus):gsub(str_const.underscore, str_const.slash)

  local reminder = #b64_str % 4
  if reminder > 0 then
    b64_str = b64_str .. string_rep(str_const.equal, 4 - reminder)
  end
  local data = ngx_decode_base64(b64_str)
  if not data then
    return nil
  end
  if json_decode then
    data = cjson_decode(data)
  end
  return data
end


local function normalize_secret_str(secret_str)
  if secret_str then
    local result = ""
    local lines = secret_str:gmatch("([^\r\n]*)[\r\n]*")
    for line in lines do
      if line:gmatch("^%s*$") ~= nil then
        local line_trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
        if #line_trimmed > 0 then
          if #result > 0 then
            result = result.."\n"
          end
          result = result..line_trimmed
        end
      end
    end
    return result
  else
    return nil
  end
end


--@function get_secret_str  : returns the secret if it is a string, or the result of a function
--@param either the string secret or a function that takes a string parameter and returns a string or nil
--@param  jwt payload
--@return the secret as a string or as a function
local function get_secret_str(secret_or_function, jwt_obj)
  if type(secret_or_function) == str_const.funct then
    -- Pull out the kid value from the header
    local kid_val = jwt_obj[str_const.header][str_const.kid]
    if kid_val == nil then
      error({reason="secret function specified without kid in header"})
    end
    -- Call the function
    return normalize_secret_str(secret_or_function(kid_val)) or error({reason="function returned nil for kid: " .. kid_val})
  elseif type(secret_or_function) == str_const.string then
    -- Just return the string
    return normalize_secret_str(secret_or_function)
  else
    -- Throw an error
    error({reason="invalid secret type (must be string or function)"})
  end
end


--@function load jwt
--@param jwt string token
--@param secret
function _M.load_jwt(self, jwt_str, secret)
  local success, ret = pcall(parse, secret, jwt_str)
  if not success then
    return {
      valid=false,
      verified=false,
      reason=ret[str_const.reason] or str_const.invalid_jwt
    }
  end

  local jwt_obj = ret
  jwt_obj[str_const.verified] = false
  jwt_obj[str_const.valid] = true
  return jwt_obj
end

--@function verify jwt object
--@param secret
--@param jwt_object
--@leeway
--@return verified jwt payload or jwt object with error code
function _M.verify_jwt_obj(self, secret, jwt_obj, ...)
  if not jwt_obj.valid then
    return jwt_obj
  end

  if jwt_obj[str_const.payload][str_const.exp] and type(jwt_obj[str_const.payload][str_const.exp]) == str_const.number then
    exp = jwt_obj[str_const.payload][str_const.exp] * 1000
    overdue = 10 * 1000
    if (ngx.now() > exp + overdue) then
      jwt_obj[str_const.reason] = "token has expired"
      return jwt_obj
    end
  end

  local alg = jwt_obj[str_const.header][str_const.alg]

  local jwt_str = string_format(str_const.regex_jwt_join_str, jwt_obj.raw_header , jwt_obj.raw_payload , jwt_obj.signature)

  local success, secret_str = pcall(get_secret_str, secret, jwt_obj)
  if not success then
    jwt_obj[str_const.reason] = secret_str[str_const.reason] or str_const.internal_error
  elseif alg == str_const.HS256 or alg == str_const.HS512 then
    local secret_key = ngx_decode_base64(secret_str)
    local raw_header = get_raw_part(str_const.header, jwt_obj)
    local raw_payload = get_raw_part(str_const.payload, jwt_obj)
    local message = string_format(str_const.regex_join_msg, raw_header , raw_payload)
    local alg = jwt_obj[str_const.header][str_const.alg]
    local signature = ""
    if alg == str_const.HS256 then
      signature = hmac:new(secret_key, hmac.ALGOS.SHA256):final(message)
    elseif alg == str_const.HS512 then
      signature = hmac:new(secret_key, hmac.ALGOS.SHA512):final(message)
    else
      signature = ""
    end
    local ret = string_format(str_const.regex_join_msg, message , _M:jwt_encode(signature))
    if jwt_str ~= ret then
      -- signature check
      jwt_obj[str_const.reason] = "signature mismatch: " .. jwt_obj[str_const.signature]
    end
  elseif alg == str_const.RS256 or alg == str_const.RS512 or alg == str_const.ES256 then
    local pubkey, err = evp.PublicKey:new(secret_str)
    if not pubkey then
      jwt_obj[str_const.reason] = "decode secret is not a valid public key: " .. (err and err or secret)
      return jwt_obj
    end
    local verifier, err = evp.PublicKeyVerifier:new(pubkey)
    if not verifier then
      -- Internal error case, should not happen...
      jwt_obj[str_const.reason] = "failed to build verifier " .. err
      return jwt_obj
    end

    -- assemble jwt parts
    local raw_header = get_raw_part(str_const.header, jwt_obj)
    local raw_payload = get_raw_part(str_const.payload, jwt_obj)

    local message = string_format(str_const.regex_join_msg, raw_header ,  raw_payload)
    local sig = _M:jwt_decode(jwt_obj[str_const.signature], false)

    if not sig then
      jwt_obj[str_const.reason] = "wrongly encoded signature"
      return jwt_obj
    end

    if alg == str_const.ES256 then
      -- asin.1 wrap the raw signature
      local r, s
      if string_byte(sig, 1) >= 127 then
        r = string_char(0x02, 33, 0)..string_sub(sig, 1, 32)
      else
        r = string_char(0x02, 32)..string_sub(sig, 1, 32)
      end
      if string_byte(sig, 33) >= 128 then
        s = string_char(0x02, 33, 0)..string_sub(sig, 33, 64)
      else
        s = string_char(0x02, 32)..string_sub(sig, 33, 64)
      end
      sig = string_char(0x30, #r+#s)..r..s
    end

    local verified = false
    local err = "verify error: reason unknown"

    if alg == str_const.RS256 or alg == str_const.ES256 then
      verified, err = verifier:verify(message, sig, evp.CONST.SHA256_DIGEST)
    elseif alg == str_const.RS512 then
      verified, err = verifier:verify(message, sig, evp.CONST.SHA512_DIGEST)
    end
    if not verified then
      jwt_obj[str_const.reason] = err
    end
  else
    jwt_obj[str_const.reason] = "unsupported algorithm " .. alg
  end

  if not jwt_obj[str_const.reason] then
    jwt_obj[str_const.verified] = true
    jwt_obj[str_const.reason] = str_const.everything_awesome
  end
  return jwt_obj

end


function _M.verify(self, secret, jwt_str, ...)
  local jwt_obj = _M.load_jwt(self, jwt_str, secret)
  if not jwt_obj.valid then
    return {verified=false, reason=jwt_obj[str_const.reason]}
  end
  return  _M.verify_jwt_obj(self, secret, jwt_obj, ...)
end

return _M
