(ns exerciser
  (:gen-class)
  (:require [no.nsd.clj-jwt]
            [buddy.core.keys :as keys]
            [buddy.sign.jwt :as jwt]
            [clj-time.core :as time]
            [clojure.pprint :as pp]
            [clojure.test :as t]
            [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.spec.gen.alpha :as gen]
            [clojure.term.colors :refer :all]))


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

(def ec-privkey   (keys/str->private-key private-rsa-key "secret"))
(def ec-pubkey    (keys/str->public-key public-rsa-key))
(def sample-claims {:sub   "f750bd26-ae85-4808-8f9a-dcc964fc8664"
                    :exp   (time/plus (time/now) (time/minutes 30))})

(def untestable-funs ['no.nsd.clj-jwt/fetch-keys
                      'no.nsd.clj-jwt/resolve-key
                      'no.nsd.clj-jwt/unsign])

(defn generate-jwt
  [claims key]
  (jwt/sign claims
            key
            {:alg :rs256
             :header {:kid "test-key"}}))

(defn init
  []
  ;; Redifine key related specs to enable generating
  (s/def :no.nsd.clj-jwt/RSAPublicKey (s/with-gen keys/public-key?
                                                  #(s/gen #{ec-pubkey})))
  (s/def :no.nsd.clj-jwt/jwt  (s/with-gen (s/nilable (s/and string?
                                                            #(re-matches no.nsd.clj-jwt/jwtregex %)))
                                          #(s/gen #{(generate-jwt sample-claims ec-privkey)})))

  ;; Stub out functions that will call external resources
  (stest/instrument [`no.nsd.clj-jwt/fetch-keys]
                    {:stub #{`no.nsd.clj-jwt/fetch-keys}}))


(defn result-type
  [ret]
  (let [failure (:failure ret)]
    (cond
      (nil? failure)                  :check-passed
      (::s/failure (ex-data failure)) :check-failed
      :default                        :check-threw)))


(defn summarizer
  "Simplified version of clojure.spec.tests summarize-results that only prints
  errors"
  [check-results]
  (reduce
   (fn [summary result]
     (when (:failure result)
       (pp/pprint (stest/abbrev-result result)))
     (-> summary
         (update :total inc)
         (update (result-type result) (fnil inc 0))))
   {:total 0}
   check-results))


(defn exercise-ns
  [ns]
  (println (bold "Exercising functions in " (name ns)))
  (init)
  (-> (stest/enumerate-namespace ns)
      (#(reduce (fn [fns f] (remove #{f} fns)) % untestable-funs))
      (stest/check {:clojure.spec.test.check/opts {:num-tests 300}})
      ((fn [results]
         (doseq [res results]
           (println (if (:failure res)
                      (red (str "x " (:sym res)))
                      (green (str "✓ " (:sym res))))))
         results))
      summarizer))


(defn -main
  [& args]
  (doseq [ns ['no.nsd.clj-jwt]]
    (let [res       (exercise-ns ns)
          successes (or (:check-passed res) 0)
          fails     (+ (or (:check-failed res) 0)
                       (or (:check-threw res) 0))]
      (if (pos? fails)
        (do (when (pos? successes)
              (println (green (str successes
                                   " function"
                                   (when (not= 1 successes) "s")
                                   " successfully exercised"))))
            (println (red (str fails
                               " function"
                               (when (> fails 1) "s")
                               " failed\n")))
            (System/exit 1))
        (println (green (str successes
                             " function"
                             (when (not= 1 successes) "s")
                             " successfully exercised\n"))))))
  (System/exit 0))

