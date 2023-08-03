(ns com.github.sikt-no.clj-jwt-test
  (:require [com.github.sikt-no.clj-jwt :as clj-jwt]
            [buddy.sign.jwt :as buddy-jwt]
            [buddy.core.keys :as buddy-keys]
            [taoensso.timbre :as timbre]
            [taoensso.timbre.tools.logging :as cljlog]
            [clojure.java.io :refer [resource]]
            [clojure.test :refer [deftest testing is]])
  (:import (java.time ZoneId ZonedDateTime)))

;; Effectively turn of logging in test
(def timbre-config  {:min-level :fatal})
(timbre/merge-config! timbre-config)
(cljlog/use-timbre)

(def example-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


(def private-rsa-key
  "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,27176ED7CC3B4C5F1061DFA491E31FE0

sAxVEIQN6aFka4ApVmag0MO5ZdhEaV0bz1dADLWnBBXRtOdyavYPDJRrzC0TgmZ5
TLUWNEeB60ja1C0iV3TskCOZ6/eMM+/ipISLbYdrz1lJ2UP0Nz+snbi4sNwvU0+t
BTe6ntB9t/cR8n7IaECN5TsaFTrVxKwg5MMXJAEMQKvC5wviNZV+mH/FlYiUG7tr
XzNOdvBkJJO2fn8JD4faQyr8bja5A9Mf0L9Z1ecBX/aGM7AjtqlUXsKbnpWnGhvY
ETLmJ19fWplSKFbsm6olc64/OLZ3m5uXTCXFviUQDZP0duu1+kXzYz2LQSIQYJy8
u4vfiWA4EDgRtbudOv+kdtRMDmY2E1H2zeJKxOpc9Z3khEjtnpoxOV+C3x+pvbfk
Lbaip/LbYujtHt70211GfZCwBBcz8X875DxqxOwg8oalPuakgI18kE+XnQ6IWB1E
NijAi4a52IDdeVsA0LDPFAcnIRed/uIeYXt7FSVfcEAgjk1K7geqa8nQP1TnPO2t
AClIq24BZ14fCpn+apup4mtMaecC8ubOmOs6UmFTZMYqQQECyFgcWx7mCaMJ2iUp
9nJQh+4brIgzIhUSweU7N02W75p+X27tUIKnHTrNIqLRudBisCUGO+oAr0e6YiTd
bM/n5trY7QVwFPiu12YY+fdZWVDa0v7Wz47+V6zBkKDd/HDB5t4zc7B7zZ9RZxs0
Yejev7Z+yRk6aZpBi+6dp/8adS5hVFGnDhKYusi03x0mBBMb1c/IPt72ZcMO5JuW
9IHZoq9ZbYk9UkQLtTgBexfK9np6vqdrTH05+wrskbSk3Gnb8uBUoUMt4AopGnlY
-----END RSA PRIVATE KEY-----")

(def public-rsa-key
  "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRTHJKynvPn+dzXX2a24hphUFg
olisO68j/ucrXKc7OQ2qPdTzVnmNXNxh+J5UxXRfE3K9hDJSK+SSHMJBPH82jVxK
vLu9XxKFHYlWPccluz3pqDfaGNPO12968DAldwvAV6hTGgx7oMaNPu0UltgD/aaj
6nO5x6zZNuMWb8blMQIDAQAB
-----END PUBLIC KEY-----")


(def ec-privkey           (buddy-keys/str->private-key private-rsa-key "secret"))
(def ec-pubkey            (buddy-keys/str->public-key public-rsa-key))
(def jwt-payload          {:sub "asd"
                           :scope "a:read  a:write\nb:read  "})
(def signed-jwt           (buddy-jwt/sign jwt-payload ec-privkey {:alg :rs256 :header {:kid "test-key"}}))
(def signed-jwt-wrongkey  (buddy-jwt/sign jwt-payload ec-privkey {:alg :rs256 :header {:kid "wrong-key"}}))

(deftest jwt-regex
  (testing "Regex should match valid jwt"
    (is (= false (nil? (re-matches clj-jwt/jwtregex example-jwt)))))
  (testing "Regex should not match if not a jwt"
    (is (nil? (re-matches clj-jwt/jwtregex "ab12356723cdb.1235412513")))))


(deftest unsign-jwt
  (testing "Unsigns jwt and returns payload"
    (is (= (clj-jwt/unsign (resource "jwks.json") signed-jwt)
           jwt-payload)))

  (testing "Fails if key referenced in jwt header is not found"
    (is (thrown? Exception
                 (clj-jwt/unsign (resource "jwks-other.json") signed-jwt)))))

(deftest extract-scope
  (testing "Nil input fails early"
    (is (thrown? AssertionError
                 (clj-jwt/scopes nil))))

  (testing "Missing scope gives empty set"
    (is (= #{} (->> (buddy-jwt/sign {:sub "jalla" :scope ""} ec-privkey {:alg :rs256 :header {:kid "test-key"}})
                    (clj-jwt/unsign (resource "jwks.json"))
                    (clj-jwt/scopes))))
    (is (= #{} (->> (buddy-jwt/sign {:sub "jalla" :scope " "} ec-privkey {:alg :rs256 :header {:kid "test-key"}})
                    (clj-jwt/unsign (resource "jwks.json"))
                    (clj-jwt/scopes))))
    (is (= #{} (->> (buddy-jwt/sign {:sub "jalla"} ec-privkey {:alg :rs256 :header {:kid "test-key"}})
                    (clj-jwt/unsign (resource "jwks.json"))
                    (clj-jwt/scopes)))))

  (testing "Scope extraction"
    (is (= (-> (clj-jwt/unsign (resource "jwks.json") signed-jwt)
               (clj-jwt/scopes))
           #{"a:read" "b:read" "a:write"}))))

(deftest verify-jwt
  (testing "Unsigns jwt and returns payload"
    (is (= (clj-jwt/unsign (resource "jwks.json") signed-jwt)
           jwt-payload)))

  (testing "Unsign supports char arrays as key"
    (is (= (clj-jwt/unsign (char-array (slurp (resource "jwks.json"))) signed-jwt)
           jwt-payload)))

  (testing "Refetches keys if no matching keys found"
    (is (= (clj-jwt/unsign (resource "jwks.json") signed-jwt)
           jwt-payload)))

  (testing "Verify token is not expired"
    (let [payload {:sub "jalla" :exp (-> (ZonedDateTime/now (ZoneId/of "UTC")) (.plusHours 1) (.toEpochSecond))}]
      (is (= (->> payload
                  (clj-jwt/sign (resource "jwks.json") "test-key")
                  (clj-jwt/unsign (resource "jwks.json")))
             payload))))

  (testing "Verify token is expired"
    (let [payload {:sub "jalla" :exp (-> (ZonedDateTime/now (ZoneId/of "UTC")) (.minusHours 1) (.toEpochSecond))}]
      (is (thrown? Exception (->> payload
                                  (clj-jwt/sign (resource "jwks.json") "test-key")
                                  (clj-jwt/unsign (resource "jwks.json")))))))

  (testing "Fails if key referenced in jwt head is not found"
    (is (thrown? Exception
                 (clj-jwt/unsign (resource "jwks-other.json") signed-jwt)))))

(deftest sign-claims
  (testing "Signs claims and return a valid jwt"
    (is (= (clj-jwt/sign (resource "jwks.json") "test-key" {:sub "foo"})
           "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJzdWIiOiJmb28ifQ.pn9YAwHb4FhEksaH9keRA9lgPh01RkkzR44u0wqDJjbXROSygCr6Ry4mT7WuGhY9ha0tBVfriN29pfnZgPiIgI3Z1xue4nMdHnveYo985xvwkW8PIP1yjbshfARscO2SdTm_odyKh-CZzpLiihfM3kpYmFhpL8-pzRLZPSnc3Jg")))
  (testing "Sign claims using char array as jwks"
    (is (= (clj-jwt/sign (char-array (slurp (resource "jwks.json"))) "test-key" {:sub "foo"})
           "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0.eyJzdWIiOiJmb28ifQ.pn9YAwHb4FhEksaH9keRA9lgPh01RkkzR44u0wqDJjbXROSygCr6Ry4mT7WuGhY9ha0tBVfriN29pfnZgPiIgI3Z1xue4nMdHnveYo985xvwkW8PIP1yjbshfARscO2SdTm_odyKh-CZzpLiihfM3kpYmFhpL8-pzRLZPSnc3Jg")))
  (testing "Verify round trip"
    (is (= (clj-jwt/unsign (resource "jwks.json") (clj-jwt/sign (resource "jwks.json") "test-key" {:sub "foo"}))
           {:sub "foo"})))
  (testing "Fails if given key-id not in jwks resource"
    (is (thrown? Exception (clj-jwt/sign (resource "jwks.json") "no-such-key" {:sub "foo"})))))
