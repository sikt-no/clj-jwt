(ns com.github.sikt-no.clj-jwt
  (:require [buddy.core.keys :as keys]
            [buddy.core.keys.jwk.proto :as buddy-jwk]
            [buddy.sign.jwt :as jwt]
            [buddy.sign.util :as util]
            [clojure.algo.generic.functor :refer [fmap]]
            [clojure.data.json :as json]
            [clojure.java.io :refer [resource]]
            [clojure.set :as set]
            [clojure.spec.gen.alpha :as gen]
            [clojure.spec.alpha :as s]
            [clojure.tools.logging :as log]
            [invetica.uri :as uri]
            [clojure.string :as str]))

(def jwtregex #"^[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?\.[a-zA-Z0-9\-_=]+?$")

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

(s/def ::key (s/keys :req-un [#{::public-key}]
                     :opt-un [::private-key]))

(s/def ::key-store (s/map-of ::kid
                             ::key))

(s/def ::resource (s/with-gen #(or (instance? java.net.URL %)
                                   (instance? (class (char-array "")) %)
                                   (and (string? %)
                                        (try
                                          (slurp %)
                                          true
                                          (catch Exception e
                                            false))))
                              ;; Always use local resources to avoid spamming actual servers
                              #(s/gen #{(resource "jwks.json")
                                        (resource "jwks-other.json")})))

(s/def ::jwks-url (s/with-gen (s/or :url :invetica.uri/absolute-uri-str
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
                :public-key #{(buddy-jwk/jwk->public-key %)}
                :private-key (buddy-jwk/jwk->private-key %)))))

(s/fdef fetch-keys
        :args (s/cat :jwks-url ::jwks-url)
        :ret (s/with-gen ::key-store
                         #(s/gen #{(->> (resource "jwks.json")
                                        slurp
                                        ((fn [jwks-string] (json/read-str jwks-string :key-fn keyword)))
                                        jwks-edn->keys)})))

(defn- fetch-keys
  "Fetches the jwks from the supplied jwks-url and converts to java Keys.
  Returns a map keyed on key-id where each value is a RSAPublicKey object"
  [jwks-url]
  (log/debug "Fetching keys from jwks-url" jwks-url)
  (try (->> jwks-url
            slurp
            (#(json/read-str % :key-fn keyword))
            jwks-edn->keys)
       (catch Throwable t (do (log/error t "Could not fetch jwks keys")
                              false))))


;; Atom to hold the public and private keys used for signature validation in memory for
;; caching purposes. The atom holds a clojure map with kid -> key pairs. Each key is a
;; clojure map containing a :public-key and optionally a :private-key.
(defonce keystore-atom
         (atom {}))

(defn- update-jwks-entry [now-ms old-keyset new-keyset]
  (let [res (with-meta
              (merge-with (fn [old-kidmap new-kidmap]
                            (merge {:public-key (set/union (get old-kidmap :public-key #{})
                                                           (get new-kidmap :public-key #{}))}
                                   (when-let [privkey (get new-kidmap :private-key
                                                           (get old-kidmap :private-key))]
                                     {:private-key privkey})))
                          old-keyset new-keyset)
              {:refreshed-at-ms now-ms})]
    res))

(defn- update-keystore [old-ks new-ks now-ms]
  (merge-with (partial update-jwks-entry now-ms) old-ks new-ks))

(defn- resolve-key
  "Returns java.security.Key given key-fn, jwks-url and :key-type in jwt-header.
  If no key is found refreshes"
  ([keystore key-type jwks-url jwt-header]
   (resolve-key keystore key-type jwks-url jwt-header (System/currentTimeMillis)))
  ([keystore key-type jwks-url jwt-header now-ms]
   (log/debug "Resolving key" jwt-header "from jwk cache for" jwks-url)
   (let [key-fn (fn [] (get-in @keystore [jwks-url (:kid jwt-header) key-type]))]
     (if-let [key (key-fn)]
       key
       (do (log/debug "Fetch and resolve key" jwt-header "from" jwks-url)
           (when-let [new-keys (with-meta (fetch-keys jwks-url)
                                          {:refreshed-at-ms now-ms})]
             (swap! keystore update-keystore {jwks-url new-keys} now-ms))
           (if-let [key (key-fn)]
             key
             (do
               (log/error "Could not locate public key corresponding to jwt header's kid:" (:kid jwt-header) "for url:" jwks-url)
               (throw (ex-info (str "Could not locate key corresponding to jwt header's kid: " (:kid jwt-header) " for url: " jwks-url)
                               {:type :validation :cause :unknown-key})))))))))


(s/fdef resolve-public-key
        :args (s/cat :jwks-url ::jwks-url
                     :jwt-header ::jwt-header)
        :ret ::public-key)

(defn resolve-public-key
  "Returns java.security.PublicKey given jwks-url and :kid in jwt-header.
  If no key is found refreshes"
  [jwks-url jwt-header]
  (first (resolve-key keystore-atom :public-key jwks-url jwt-header)))


(s/fdef resolve-private-key
        :args (s/cat :jwks-url ::jwks-url
                     :jwt-header ::jwt-header)
        :ret ::private-key)

(def resolve-private-key
  (partial resolve-key keystore-atom :private-key))


(s/fdef unsign
        :args (s/cat :jwks-url ::jwks-url
                     :token ::jwt)
        :ret ::claims)

(defn- remove-bearer [token]
  (if (and token (str/starts-with? (str/lower-case token) "bearer "))
    (subs token (count "Bearer "))
    token))

(defn- try-unsign [token opts key-set throw?]
  (let [res (reduce
              (fn [_ key-entry]
                (try
                  (reduced (jwt/unsign token key-entry (merge {:alg :rs256} opts)))
                  (catch Throwable t t)))
              nil
              key-set)]
    (if (and throw? (instance? Throwable res))
      (throw res)
      res)))

(defn unsign
  "Given jwks-url, token, and optionally opts validates and returns the claims
  of the given json web token. Opts are the same as buddy-sign.jwt/unsign."
  ([jwks-url token]
   (unsign jwks-url token {}))
  ([jwks-url token {:keys [keystore now-ms allow-refresh-after-ms]
                    :or   {keystore               keystore-atom
                           now-ms                 (System/currentTimeMillis)
                           allow-refresh-after-ms 60000}
                    :as   opts}]
   (assert (s/valid? ::jwks-url jwks-url) (str "jwks-url must conform to ::jwks-url. Was given: " jwks-url))
   (let [token (remove-bearer token)]
     (assert (s/valid? ::jwt token) "token must conform to ::jwt")
     (let [[header _payload _signature] (some-> token (str/split #"\." 3))
           header-data (util/parse-jose-header header)
           key-set (resolve-key keystore :public-key jwks-url header-data now-ms)
           ks-org @keystore
           res (try-unsign token opts key-set false)
           past-refresh-ms (some-> (get ks-org jwks-url)
                                   (meta)
                                   (get :refreshed-at-ms now-ms))
           diff-ms (- now-ms past-refresh-ms)]
       (cond
         (and
           (instance? Throwable res)
           (> diff-ms allow-refresh-after-ms))
         (let [new-ks (atom {})
               new-key-set (resolve-key new-ks :public-key jwks-url header-data now-ms)]
           (if (not= new-key-set key-set)
             (let [res (try-unsign token opts new-key-set true)]
               (swap! keystore update-keystore @new-ks now-ms)
               res)
             (throw res)))

         (instance? Throwable res)
         (throw res)

         :else
         res)))))

(defn scopes
  "Given the claims from unsign returns the jwt scope as a set of strings.

  For a jwt without scope, an empty set will be returned."
  [claims]
  (assert (map? claims) "claims must be a map!")
  (if-let [claims (not-empty (get claims :scope))]
    (do
      (assert (string? claims) ":scope in claims must be a string!")
      (into (sorted-set) (str/split claims #"\s+")))
    #{}))

(s/fdef sign
        :args (s/cat :jwks-url ::jwks-url
                     :kid ::kid
                     :claims ::claims)
        :ret ::jwt)

(defn sign
  "Given jwks-url, claims and optionally opts signs claims and returns a token. Uses
  the private key in the jwks to sign. Opts are the same as buddy-sign.jwt/sign."
  ([jwks-url kid claims]
   (sign jwks-url kid claims {}))
  ([jwks-url kid claims options]
   (assert (s/valid? ::jwks-url jwks-url) "jwks-url must conform to ::jwks-url")
   (jwt/sign claims (resolve-private-key jwks-url {:kid kid}) (merge-with merge {:alg :rs256 :header {:kid kid}} options))))

(comment
  (unsign "https://example.org"
          (str "Bearer "
               "eyJraWQiOiJjQTdxRzJnQnc3QTdJQlc0TVpncFlvcHpSYUx5a3NDTDRoUWV4QVhuX2VFIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJmODA2NDYyNS0xYzZjLTQ0MTQtYmY5My01YTQ2NmY1NTliMmUiLCJpc3MiOiJodHRwczpcL1wvc3NvLXN0YWdlLm5zZC5ubyIsIm5hbWUiOiJJdmFyIFJlZnNkYWwiLCJleHAiOjE1Nzg0MzE1MjAsIm5vbmNlIjoiNlpWZ3BTNnk1SlVqN1I4ZUE3VFUiLCJqdGkiOiI1NTgyYzBjNC0wOGY0LTQ3MWEtOGVmOS01YzEwNTNjOTQyZWUiLCJlbWFpbCI6Ikl2YXIuUmVmc2RhbEBuc2Qubm8iLCJhdXRob3JpdGllcyI6W119.Lc51W1XBv4VakKOgENmR23oCa-2DQm0CrYwfoWkQ1Lq5UoaQYxvxLm6PV4WYqNddCgmX5dGAVq1KkThgu1ra-1IXjb8bTY7HVZ6b6if_NGAoBfcm7_zbZsCp6MNSqBXhIq4B5rPmasLMWzJi09xVBEYT34JuomsL3JsYhPjvu44pXZpYoIeo8yV2PC8QwxFShIte1g6l7bVDOI8jVuW9CIi_R5tncv-i2rovN41mYtpp-GHDMyMHx-Y7Gli0ANX9vnHIDjFYV6LqbcQlri0HP62Uvcm5C0BW1LBsDZqP2oOWStykTIDLDMfyEIKu7ng-q3JxBDC7ItujjQXZNThCCA")))

(comment
  (unsign "https://sso-stage.nsd.no/.well-known/jwks.json"
          (str "Bearer "
               "eyJraWQiOiJjQTdxRzJnQnc3QTdJQlc0TVpncFlvcHpSYUx5a3NDTDRoUWV4QVhuX2VFIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJmODA2NDYyNS0xYzZjLTQ0MTQtYmY5My01YTQ2NmY1NTliMmUiLCJpc3MiOiJodHRwczpcL1wvc3NvLXN0YWdlLm5zZC5ubyIsIm5hbWUiOiJJdmFyIFJlZnNkYWwiLCJleHAiOjE1Nzg0MzE1MjAsIm5vbmNlIjoiNlpWZ3BTNnk1SlVqN1I4ZUE3VFUiLCJqdGkiOiI1NTgyYzBjNC0wOGY0LTQ3MWEtOGVmOS01YzEwNTNjOTQyZWUiLCJlbWFpbCI6Ikl2YXIuUmVmc2RhbEBuc2Qubm8iLCJhdXRob3JpdGllcyI6W119.Lc51W1XBv4VakKOgENmR23oCa-2DQm0CrYwfoWkQ1Lq5UoaQYxvxLm6PV4WYqNddCgmX5dGAVq1KkThgu1ra-1IXjb8bTY7HVZ6b6if_NGAoBfcm7_zbZsCp6MNSqBXhIq4B5rPmasLMWzJi09xVBEYT34JuomsL3JsYhPjvu44pXZpYoIeo8yV2PC8QwxFShIte1g6l7bVDOI8jVuW9CIi_R5tncv-i2rovN41mYtpp-GHDMyMHx-Y7Gli0ANX9vnHIDjFYV6LqbcQlri0HP62Uvcm5C0BW1LBsDZqP2oOWStykTIDLDMfyEIKu7ng-q3JxBDC7ItujjQXZNThCCA")))

(comment
  (unsign "https://sso.nsd.no/.well-known/jwks.json"
          (str "Bearer "
               "eyJraWQiOiJjQTdxRzJnQnc3QTdJQlc0TVpncFlvcHpSYUx5a3NDTDRoUWV4QVhuX2VFIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJmODA2NDYyNS0xYzZjLTQ0MTQtYmY5My01YTQ2NmY1NTliMmUiLCJpc3MiOiJodHRwczpcL1wvc3NvLXN0YWdlLm5zZC5ubyIsIm5hbWUiOiJJdmFyIFJlZnNkYWwiLCJleHAiOjE1Nzg0MzE1MjAsIm5vbmNlIjoiNlpWZ3BTNnk1SlVqN1I4ZUE3VFUiLCJqdGkiOiI1NTgyYzBjNC0wOGY0LTQ3MWEtOGVmOS01YzEwNTNjOTQyZWUiLCJlbWFpbCI6Ikl2YXIuUmVmc2RhbEBuc2Qubm8iLCJhdXRob3JpdGllcyI6W119.Lc51W1XBv4VakKOgENmR23oCa-2DQm0CrYwfoWkQ1Lq5UoaQYxvxLm6PV4WYqNddCgmX5dGAVq1KkThgu1ra-1IXjb8bTY7HVZ6b6if_NGAoBfcm7_zbZsCp6MNSqBXhIq4B5rPmasLMWzJi09xVBEYT34JuomsL3JsYhPjvu44pXZpYoIeo8yV2PC8QwxFShIte1g6l7bVDOI8jVuW9CIi_R5tncv-i2rovN41mYtpp-GHDMyMHx-Y7Gli0ANX9vnHIDjFYV6LqbcQlri0HP62Uvcm5C0BW1LBsDZqP2oOWStykTIDLDMfyEIKu7ng-q3JxBDC7ItujjQXZNThCCA")))
