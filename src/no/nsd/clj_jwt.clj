(ns no.nsd.clj-jwt
  (:require [buddy.core.keys :as keys]
            [buddy.core.keys.jwk.proto :as buddy-jwk]
            [buddy.sign.jwt :as jwt]
            [clojure.algo.generic.functor :refer [fmap]]
            [clojure.data.json :as json]
            [clojure.java.io :refer [resource]]
            [clojure.spec.gen.alpha :as gen]
            [clojure.spec.alpha :as s]
            [invetica.uri :as uri]))


(def jwtregex  #"^[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?$")

(s/def ::sub (s/nilable :no.nsd.authorizer/uuid))

(s/def ::kid string?)

(s/def ::scope (s/nilable string?))

(s/def ::scopes (s/nilable (s/coll-of string? :kind set?)))

(s/def ::exp (s/and integer?
                    pos?))

(s/def ::kty (s/with-gen (s/and string?
                                #(= "RSA" %))
               #(s/gen #{"RSA"})))

(s/def ::n (s/with-gen string?
             #(s/gen #{;;valid:
                       "nZq9S6leC-8Se5-VlHcVZ0HVpQRwFNuZRp82WFddhMZUoEEKybuiym6uNh5kquNADbZcRw4yxJI3BBuWLoOz-YBjXlnxNqeQgr2E8LZ_AsT-6Yb6xdKrZ5acXaLAQsXwk53GHhUcFzOFu3u6BXVMknCY6jI6dxgOlSlWQV2nCjWTio_cTbDjsSSfIQ9jWcK9aCmw37omCZqIXlLwGA9fD4Ah8c4-QTfV7dZ7q_MQmrCqv88_eYAvg-lUlUQRnB9jGg53MWlitYGKW_aUr8oRn7nHm-gsXtL_bzWLxSSbkxiht52e4mcFNOXAqXVlocW1YJC3weRojI-CXJZ6218z6Q"
                       ;;invalid:
                       "xnmcbvjksdhfwiuerfsdjbsdkjfghwileugkhjbvnxdvjbvwiuerhslkdjbvvklwl4iuhjxcvxnmbvkwerjlfhiwuerhsjdkdfkjbvwe4riefslkv-dlsfkjhwpoiefhcvsdjkhvowpefwoeifhv_sdøflkhjwpeoifhsvøkl"})))

(s/def ::e string?)

(s/def ::subject (s/nilable (s/keys :req-un [::sub ::exp]
                                    :opt-un [::scope
                                             ::scopes])))

(s/def ::jwt (s/nilable (s/and string?
                               #(re-matches jwtregex %))))

(s/def ::jwk (s/keys :req-un [::kty ::e ::n ::kid]))

(s/def ::RSAPublicKey keys/public-key?)

(s/def ::key-store (s/map-of ::kid
                             ::RSAPublicKey))

(s/def ::resource (s/with-gen #(instance? java.net.URL %)
                   #(s/gen #{(resource "jwks.json")
                             (resource "jwks-other.json")})))


(s/fdef jwks-edn->public-keys
        :args (s/cat :jwks (s/coll-of ::jwk :type vector?))
        :ret ::key-store)

(defn jwks-edn->public-keys
  "Transform vector of json-web-keys to map of kid -> PublicKey pairs."
  [json-web-keys]
  (->> json-web-keys
       :keys
       (filter #(= (:kty %) "RSA"))
       (group-by :kid)
       (fmap first)
       (fmap buddy-jwk/jwk->public-key)))


(s/fdef fetch-keys
        :args (s/cat :jwks-url (s/or :url      :invetica.uri/absolute-uri                                                                                                                                
                                     :resource ::resource))
        :ret  ::key-store)

(defn fetch-keys
  "Fetches the jwks from the supplied jwks-url and converts to java Keys.
  Returns a map keyed on key-id where each value is a RSAPublicKey object"
  [jwks-url]
  (->> jwks-url
      slurp
      (#(json/read-str % :key-fn keyword))
      jwks-edn->public-keys))


(def public-keys
    "Atom to hold the public keys used for signature validation in memory for
    caching purposes. The atom holds a clojure map with kid -> PublicKey pairs."
    (atom {}))


(defn refresh-keys
  "Fetches keys and updates key store (atom)"
  [jwks-url]
  (reset! public-keys
          (fetch-keys jwks-url)))


(defn resolve-key
  "Returns java.security.PublicKey given jwks-url and :kid in jwt-header.
  If no key is found refreshes"
  [jwks-url jwt-header]
  (let [key-fn (fn [] (get (deref public-keys) (:kid jwt-header)))]
    (if-let [key (key-fn)]
      key
      (do (reset! public-keys (fetch-keys jwks-url))
          (if-let [key (key-fn)]
            key
            (throw (ex-info "Could not locate public key corresponding to jwt header's kid."
                            {:type :validation :cause :unknown-key})))))))


(defn unsign
  "Given token, jwks-url, and optionally opts validates and returns the claims
  of the given json web token. Opts are the same as buddy-sign.jwt/unsign."
  ([token jwks-url]
   (unsign token jwks-url {})) 
  ([token jwks-url opts]
   (jwt/unsign token (partial resolve-key jwks-url) (merge {:alg :rs256} opts))))

