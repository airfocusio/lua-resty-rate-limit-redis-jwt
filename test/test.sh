#!/bin/sh

function test {
  JWT_HS256_USER1="eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJ1c2VyOjEifQ.hUsPgxd0QTaaH5BhkcYVdSxmJXATA5v_KAWeYAL6uVM"
  JWT_HS256_USER2="eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJ1c2VyOjIifQ.qyrfIx0E6194v5XIhk22_geV0aSgoEdxVk4dv_FOiEo"
  JWT_RS256_USER3="eyJraWQiOiIyIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1c2VyOjMifQ.GN_5KmuZ-hKs9JXpI_TQnxvCCFRBgvc71vpBlDvgkOaXP5hALm1hfmv0ZAknLfFgKi-XqU5tYOwGWJmEJHrhi4fMusugpyqBKLNdEfZA1meZ3AYlBCCPPoS0B6i9hAPhdiiMu7L18i_0l_oQJkkQ9Dn7RT8ts7kb2M2JkR0WQMmxb8oOM_xNiji2AVk5x45DY4JI_4AWx7aoHOQDb4M35BpHiDA9qxiubHOaEIjaHSgyhrf_61cidCuPsGftbNQijh0qf6yBp10598bVewSsjH9uazOedOa7j7MPWz3X8e_0HphJZMxpdS0gVs_IczabOFvBNDJLcHdi89NhebZqnA"
  JWT_RS256_USER4="eyJraWQiOiIyIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ1c2VyOjQifQ.bt9ap6JFlg9uLWVSv2Mp-Y3edLTiDrAjyrVqMWQW5gOObZEBCpbgw1VLS2yHmE3VvkOs-O1oCJ8u_w6LB0OXr4k_YOHSbJiIep7a2fm09UDwSTt6jZpOqxtO8DkGvbF5563jDFfGqIUQ81YbVPVZziKqGLpSXwyP6MfPJwVOqoMgMma0K-cJs72dST4y3cO441PYzC-Xrf7yiGe87QV9XmZRvxKjyZUmMhUupz21pLVYOyrZ0w2B7J8a4vU_9joiydEpHEoimLPC6qd2-56DHqY-gw4Q_O4GPYwoiOR6it4R6zcAlT6EUG19uejCWZP2qkm_CLTt8DV-km9KZ-NHKw"
  JWT_ES256_USER5="eyJraWQiOiIzIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ1c2VyOjUifQ.eL5porEZxBCCAdzljkZkvAMkNb5ZiYMDHNfl2WKgAyRs7QDT8GmTHkUrAnUmTrwAAs4y91Z30oZqL600KceL_Q"
  JWT_ES256_USER6="eyJraWQiOiIzIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ1c2VyOjYifQ.sob2SDlJbpmf0Dt6IE3YQvkhlVK-vjTCqcKZyiIkDnt6DBcRyVP4BeRkSWlV_8VyHiQddcED-F-uZhejAR3ZFg"
  JWT_HS256_USER7_EXPIRED="eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJ1c2VyOjciLCJleHAiOjB9.OD-bE4Vur2CsO0hQaDGfZsiv-QzUH7W24_QAnkO_D6A"
  JWT_HS256_USER8_INVALID="eyJraWQiOiIxIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiJ1c2VyOjgifQ.Tx0KvCj3mvxCyWcBYPF9skutisKTGK5ezMtnOmmpzUc"

  echo "Anonymous"
  curl -s localhost/api/ -I -XGET | grep "200 OK"
  curl -s localhost/api/ -I -XGET | grep "429 Too Many Requests"

  echo "HS256"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER1" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER2" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER1" | grep "X-RateLimit-Remaining: 0"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER2" | grep "X-RateLimit-Remaining: 0"

  echo "RS256"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_RS256_USER3" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_RS256_USER4" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_RS256_USER3" | grep "X-RateLimit-Remaining: 0"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_RS256_USER4" | grep "X-RateLimit-Remaining: 0"

  echo "ES256"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_ES256_USER5" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_ES256_USER6" | grep "X-RateLimit-Remaining: 1"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_ES256_USER5" | grep "X-RateLimit-Remaining: 0"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_ES256_USER6" | grep "X-RateLimit-Remaining: 0"

  echo "Expired"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER7_EXPIRED" | grep "429 Too Many Requests"
  echo "Invalid"
  curl -s localhost/api/ -I -XGET -H "Authorization: Bearer $JWT_HS256_USER8_INVALID" | grep "429 Too Many Requests"

  echo "Includes/Excludes"
  curl -s localhost/api/unlimited/ -I -XGET | grep "200 OK"
  curl -s localhost/api/unlimited/ -I -XGET | grep "200 OK"
  curl -s localhost/api/unlimited/ -I -XGET | grep "200 OK"
  curl -s localhost/other/ -I -XGET | grep "200 OK"
  curl -s localhost/other/ -I -XGET | grep "200 OK"
  curl -s localhost/other/ -I -XGET | grep "200 OK"
}

docker-compose up -d
docker-compose logs -f nginx &
(set -eo pipefail; test)
code=$?
docker-compose kill &>/dev/null || true
docker-compose rm -f &>/dev/null || true
exit $code
