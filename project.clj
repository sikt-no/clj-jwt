(defproject no.nsd/clj-jwt "0.4.2"
  :description "A Clojure library to fetch json web keys and validate json web tokens. Wraps Buddy."
  :url "https://gitlab.nsd.no/clojure/clj-jwt"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :middleware [lein-tools-deps.plugin/resolve-dependencies-with-deps-edn]
  :plugins [[lein-tools-deps "0.4.1"]]
  :lein-tools-deps/config {:config-files [:project]}
  :repositories [["central"   {:url "https://nexus.nsd.no/repository/nsd-maven-public"}]
                 ["snapshots" {:url "https://nexus.nsd.no/repository/nsd-maven-public-snapshots"}]
                 ["releases"  {:url "https://nexus.nsd.no/repository/nsd-maven-public-releases"}]])
