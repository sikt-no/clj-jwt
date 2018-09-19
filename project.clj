(defproject no.nsd/clj-jwt "0.2.0"
  :description "A Clojure library to fetch json web keys and validate json web tokens. Wraps Buddy."
  :url "https://gitlab.nsd.no/clojure/clj-jwt"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :middleware [lein-tools-deps.plugin/resolve-dependencies-with-deps-edn]
  :plugins [[lein-tools-deps "0.4.1"]]
  :lein-tools-deps/config {:config-files [:project]}
  :repositories [["snapshots" {:url "https://nexus.nsd.no/repository/maven-snapshots/"
                               :creds :gpg}]
                 ["releases"  {:url "https://nexus.nsd.no/repository/maven-releases/"
                               :creds :gpg}]])
