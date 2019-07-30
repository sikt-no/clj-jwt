(ns no.nsd.clj-jwt
  (:require [buddy.core.keys :as keys]
            [buddy.core.keys.jwk.proto :as buddy-jwk]
            [buddy.sign.jwt :as jwt]
            [clojure.algo.generic.functor :refer [fmap]]
            [clojure.data.json :as json]
            [clojure.java.io :refer [resource]]
            [clojure.spec.gen.alpha :as gen]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [invetica.uri :as uri]))

(def jwtregex  #"^[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?$")

(s/def ::sub (s/nilable string?))

(s/def ::kid (s/with-gen (s/nilable string?)
               #(s/gen #{"test-key"})))

(s/def ::scope (s/nilable string?))

(s/def ::scopes (s/nilable (s/coll-of string? :kind set?)))

(s/def ::exp (s/nilable (s/and integer?
                               pos?)))

(s/def ::kty (s/with-gen (s/nilable (s/and string?
                                           #(= "RSA" %)))
               #(s/gen #{"RSA" nil})))

;; n is the public key component of a json web key
(s/def ::n (s/with-gen string?
             #(s/gen #{;;valid:
                       "nZq9S6leC-8Se5-VlHcVZ0HVpQRwFNuZRp82WFddhMZUoEEKybuiym6uNh5kquNADbZcRw4yxJI3BBuWLoOz-YBjXlnxNqeQgr2E8LZ_AsT-6Yb6xdKrZ5acXaLAQsXwk53GHhUcFzOFu3u6BXVMknCY6jI6dxgOlSlWQV2nCjWTio_cTbDjsSSfIQ9jWcK9aCmw37omCZqIXlLwGA9fD4Ah8c4-QTfV7dZ7q_MQmrCqv88_eYAvg-lUlUQRnB9jGg53MWlitYGKW_aUr8oRn7nHm-gsXtL_bzWLxSSbkxiht52e4mcFNOXAqXVlocW1YJC3weRojI-CXJZ6218z6Q"
                       ;;invalid:
                       "xnmcbvjksdhfwiuerfsdjbsdkjfghwileugkhjbvnxdvjbvwiuerhslkdjbvvklwl4iuhjxcvxnmbvkwerjlfhiwuerhsjdkdfkjbvwe4riefslkv-dlsfkjhwpoiefhcvsdjkhvowpefwoeifhv_sdøflkhjwpeoifhsvøkl"})))

;; d is the private key component of a json web key
(s/def ::d (s/with-gen string?
             #(s/gen #{;; Valid:
                       "PJrXSYLiYRebbJN4yHujP3LfoHzCEnVh3Jl2FN9KaWK260HmROQYZG-sPQ5Bwqg-bz1xbyE1dQfSsuBy-3LqHrqM-ilsvcNZqQEY9R52d9D6kXmTSNMHx-3jGQ0SeO0eIFMHffLHOomvECPEKZkSPB65rijLcKQKmbnA_OlF_EE"
                       ;; Invalid:
                       "xnmcbvjksdhfwiuerfsdjbsdkjfghwileugkhjbvnxdvjbvwiuerhslkdjbvvklwl4iuhjxcvxnmbvkwerjlfhiwuerhsjdkdfkjbvwe4riefslkv-dlsfkjhwpoiefhcvsdjkhvowpefwoeifhv_sdøflkhjwpeoifhsvøkl"})))

(s/def ::e string?)

(s/def ::claims (s/keys :opt-un [::exp
                                 ::scope
                                 ::scopes
                                 ::sub]))

(s/def ::jwt (s/nilable (s/with-gen (s/and string?
                                           #(re-matches jwtregex %))
                          #(s/gen #{(jwt/sign (gen/generate (s/gen ::claims))
                                              "secret")}))))

(s/def ::jwt-header (s/keys :req-un [::kid ::kty]))

(s/def ::jwk (s/keys :req-un [::kty ::e ::n ::kid]))

(s/def ::public-key keys/public-key?)

(s/def ::private-key keys/private-key?)

(s/def ::key (s/keys :req-un [::public-key]
                     :opt-un [::private-key]))

(s/def ::key-store (s/map-of ::kid
                             ::key))

(s/def ::resource (s/with-gen #(instance? java.net.URL %)
                    ;; Always use local resources to avoid spamming actual servers
                    #(s/gen #{(resource "jwks.json")
                              (resource "jwks-other.json")})))

(s/def ::jwks-url (s/with-gen (s/or :url  :invetica.uri/absolute-uri
                                    :resource ::resource)
                    ;; Always use local resources to avoid spamming actual servers
                    #(s/gen #{(resource "jwks.json")
                              (resource "jwks-other.json")})))

(s/fdef jwks-edn->keys
  :args (s/cat :jwks (s/coll-of ::jwk :type vector?))
  :ret ::key-store)

(defn- jwks-edn->keys
  "Transform a vector of json web keys into a map of kid -> key pairs where each key is a map
  of :public-key and optionally :private-keys."
  [json-web-keys]
  (->> json-web-keys
       :keys
       (filter #(= (:kty %) "RSA"))
       (group-by :kid)
       (fmap first)
       (fmap #(assoc {}
                     :public-key (buddy-jwk/jwk->public-key %)
                     :private-key (buddy-jwk/jwk->private-key %)))))

(s/fdef fetch-keys
  :args (s/cat :jwks-url ::jwks-url)
  :ret  (s/with-gen ::key-store
          #(s/gen #{(->> (resource "jwks.json")
                         slurp
                         ((fn [jwks-string] (json/read-str jwks-string :key-fn keyword)))
                         jwks-edn->keys)})))

(defn- fetch-keys
  "Fetches the jwks from the supplied jwks-url and converts to java Keys.
  Returns a map keyed on key-id where each value is a RSAPublicKey object"
  [jwks-url]
  (log/info "Fetching keys from jwks-url" jwks-url)
  (try  (->> jwks-url
             slurp
             (#(json/read-str % :key-fn keyword))
             jwks-edn->keys)
        (catch Exception e (do (log/error "Could not fetch jwks keys")
                               false))))


;; Atom to hold the public and private keys used for signature validation in memory for
;; caching purposes. The atom holds a clojure map with kid -> key pairs. Each key is a
;; clojure map containing a :public-key and optionally a :private-key.
(defonce keystore
  (atom {}))


(defn- resolve-key
  "Returns java.security.Key given key-fn, jwks-url and :key-type in jwt-header.
  If no key is found refreshes"
  [key-type jwks-url jwt-header]
  (log/debug "Resolving key" jwt-header "from jwk cache for" jwks-url)
  (let [key-fn (fn [] (get-in @keystore [(:kid jwt-header) key-type]))]
    (if-let [key (key-fn)]
      key
      (do (log/info "Fetch and resolve key" jwt-header "from" jwks-url)
          (reset! keystore (or (fetch-keys jwks-url) @keystore))
          (if-let [key (key-fn)]
            key
            (do
              (log/info "Could not locate public key corresponding to jwt header's kid: " (:kid jwt-header))
              (throw (ex-info (str "Could not locate key corresponding to jwt header's kid: " (:kid jwt-header))
                              {:type :validation :cause :unknown-key}))))))))


(s/fdef resolve-public-key
  :args (s/cat :jwks-url    ::jwks-url
               :jwt-header  ::jwt-header)
  :ret  ::public-key)

(def resolve-public-key
  "Returns java.security.PublicKey given jwks-url and :kid in jwt-header.
  If no key is found refreshes"
  (partial resolve-key :public-key))


(s/fdef resolve-private-key
  :args (s/cat :jwks-url ::jwks-url
               :jwt-header ::jwt-header)
  :ret  ::private-key)

(def resolve-private-key
  (partial resolve-key :private-key))


(s/fdef unsign
  :args (s/cat :jwks-url ::jwks-url
               :token    ::jwt)
  :ret  ::claims)

(defn unsign
  "Given jwks-url, token, and optionally opts validates and returns the claims
  of the given json web token. Opts are the same as buddy-sign.jwt/unsign."
  ([jwks-url token]
   (unsign jwks-url token {}))
  ([jwks-url token opts]
   (jwt/unsign token (partial resolve-public-key jwks-url) (merge {:alg :rs256} opts))))

(s/fdef sign
  :args (s/cat :jwks-url ::jwks-url
               :kid      ::kid
               :claims   ::claims)
  :ret ::jwt)

(defn sign
  "Given jwks-url, claims and optionally opts signs claims and returns a token. Uses
  the private key in the jwks to sign. Opts are the same as buddy-sign.jwt/sign."
  ([jwks-url kid claims]
   (sign jwks-url kid claims {}))
  ([jwks-url kid claims options]
   (jwt/sign claims (resolve-private-key jwks-url {:kid kid}) (merge {:alg :rs256} options))))

