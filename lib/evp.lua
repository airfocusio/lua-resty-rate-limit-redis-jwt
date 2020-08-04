-- original from https://github.com/SkyLothar/lua-resty-jwt
-- see evp.license-original.md

local ffi = require "ffi"
local _C = ffi.C
local _M = { _VERSION = "0.1.0" }

local CONST = {
    SHA256_DIGEST = "SHA256",
    SHA512_DIGEST = "SHA512",
}
_M.CONST = CONST


-- see https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
ffi.cdef[[
// Error handling
unsigned long ERR_get_error(void);
const char *ERR_reason_error_string(unsigned long e);

// Basic IO
typedef struct bio_st BIO;
typedef struct bio_method_st BIO_METHOD;
BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new(BIO_METHOD *type);
int	BIO_puts(BIO *bp,const char *buf);
void BIO_vfree(BIO *a);
int BIO_write(BIO *b, const void *buf, int len);
typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

// EVP PKEY
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_rsa_st EVP_PKEY_RSA;
typedef struct evp_pkey_ec_st EVP_PKEY_EC;
EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_base_id(const EVP_PKEY *pkey);

// PUBKEY
typedef struct rsa_st RSA;
typedef struct ec_key_st EC_KEY;
EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

// EVP Sign/Verify
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct env_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
const EVP_MD *EVP_get_digestbyname(const char *name);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d, size_t cnt);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t siglen);
]]


local function _err(ret)
    local code = _C.ERR_get_error()
    if code == 0 then
        return ret, "Zero error code (null arguments?)"
    end
    return ret, ffi.string(_C.ERR_reason_error_string(code))
end


local PublicKeyVerifier = {}
_M.PublicKeyVerifier = PublicKeyVerifier

function PublicKeyVerifier.new(self, key_source)
    if not key_source then
        return nil, "You must pass in an key_source for a public key"
    end
    local evp_public_key = key_source.public_key
    self.evp_pkey = evp_public_key
    return self, nil
end

function PublicKeyVerifier.verify(self, message, sig, digest_name)
    local md = _C.EVP_get_digestbyname(digest_name)
    if not md then
        return _err(false)
    end

    local ctx = _C.EVP_MD_CTX_new()
    if not ctx then
        return _err(false)
    end
    ffi.gc(ctx, _C.EVP_MD_CTX_free)

    if _C.EVP_DigestInit_ex(ctx, md, nil) ~= 1 then
        return _err(false)
    end

    local ret = _C.EVP_DigestVerifyInit(ctx, nil, md, nil, self.evp_pkey)
    if ret ~= 1 then
        return _err(false)
    end
    if _C.EVP_DigestUpdate(ctx, message, #message) ~= 1 then
        return _err(false)
    end
    local sig_bin = ffi.new("unsigned char[?]", #sig)
    ffi.copy(sig_bin, sig, #sig)
    if _C.EVP_DigestVerifyFinal(ctx, sig_bin, #sig) == 1 then
        return true, nil
    else
        return false, "Verification failed"
    end
end


local PublicKey = {}
_M.PublicKey = PublicKey

function PublicKey.new(self, payload)
    if not payload then
        return nil, "Must pass a PEM public key"
    end
    local bio = _C.BIO_new(_C.BIO_s_mem())
    ffi.gc(bio, _C.BIO_vfree)
    local pkey
    if payload:find('-----BEGIN') then
        if _C.BIO_puts(bio, payload) < 0 then
            return _err()
        end
        pkey = _C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
    else
        return nil, "Must pass a PEM public key"
    end
    if not pkey then
        return _err()
    end
    ffi.gc(pkey, _C.EVP_PKEY_free)
    self.public_key = pkey
    return self, nil
end


return _M
