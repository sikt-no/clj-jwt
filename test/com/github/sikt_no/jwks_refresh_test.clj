(ns com.github.sikt-no.jwks-refresh-test
  (:require [aleph.http :as http]
            [aleph.netty :as netty]
            [buddy.core.keys :as buddy-keys]
            [buddy.sign.jwt :as buddy-jwt]
            [cheshire.core :as cheshire]
            [clojure.test :refer [deftest is]]
            [com.github.sikt-no.clj-jwt :as clj-jwt]
            [taoensso.timbre :as timbre]
            [taoensso.timbre.tools.logging :as cljlog])
  (:import (java.net InetSocketAddress)
           (java.util.concurrent TimeUnit)
           (okhttp3.tls HeldCertificate$Builder)))

(def timbre-config {:min-level :fatal})
(timbre/merge-config! timbre-config)
(cljlog/use-timbre)

(defonce keypair-1 (-> (HeldCertificate$Builder.)
                       (.rsa2048)
                       (.certificateAuthority 0)
                       (.duration 1000 TimeUnit/MINUTES)
                       (.build)
                       (.keyPair)))

(defonce keypair-2 (-> (HeldCertificate$Builder.)
                       (.rsa2048)
                       (.certificateAuthority 0)
                       (.duration 1000 TimeUnit/DAYS)
                       (.build)
                       (.keyPair)))

(deftest refresh-test
  (let [req-count (atom 0)
        keystore (atom {})
        jwks-endpoint (atom keypair-1)
        handler (fn [_]
                  (swap! req-count inc)
                  {:status  200
                   :headers {"content-type" "application/json"}
                   :body    (cheshire/generate-string
                              {:keys [(-> @jwks-endpoint
                                          (.getPublic)
                                          (buddy-keys/public-key->jwk)
                                          (assoc :kid "test-key"))]})})]
    (with-open [server (http/start-server handler {:socket-address (InetSocketAddress. "127.0.0.1" 0)})]
      (let [url (str "http://127.0.0.1:" (netty/port server) "/.well-known/jwks.json")
            signed-1 (buddy-jwt/sign {:sub "keypair-1"} (.getPrivate keypair-1) {:alg :rs256 :header {:kid "test-key"}})
            signed-2 (buddy-jwt/sign {:sub "keypair-2"} (.getPrivate keypair-2) {:alg :rs256 :header {:kid "test-key"}})]
        (is (= 0 @req-count))
        (is (= {:sub "keypair-1"} (clj-jwt/unsign url signed-1 {:keystore keystore})))
        (is (= 1 @req-count))

        ; endpoint has changed, but not enough time has passed to allow for a re-fetch:
        (reset! jwks-endpoint keypair-2)
        (is (= {:type :validation, :cause :signature}
               (try
                 (clj-jwt/unsign url signed-2 {:keystore keystore})
                 (catch Throwable t
                   (ex-data t)))))
        (is (= 1 @req-count))

        ; enough time has passed, verify that unsign will re-fetch the keys:
        (let [old-ks @keystore]
          (is (= {:sub "keypair-2"}
                 (try
                   (clj-jwt/unsign url signed-2 {:keystore keystore :now-ms (+ 60001 (System/currentTimeMillis))})
                   (catch Throwable t
                     (ex-data t)))))
          (is (not= old-ks @keystore)))
        (is (= 2 @req-count))

        ; another check to see that the new keystore is indeed persisted,
        ; and that keys are not re-fetched again:
        (is (= {:sub "keypair-2"}
               (try
                 (clj-jwt/unsign url signed-2 {:keystore keystore :now-ms (+ 60001 (System/currentTimeMillis))})
                 (catch Throwable t
                   (ex-data t)))))
        (is (= 2 @req-count))))))
