(defproject no.nsd/clj-jwt "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :middleware [lein-tools-deps.plugin/resolve-dependencies-with-deps-edn]
  :plugins [[lein-tools-deps "0.4.1"]]
  :lein-tools-deps/config {:config-files [:project]}
  :profiles {:test {:resource-paths ["test-resources"]
                    :dependencies [[org.clojure/test.check "0.9.0"]
                                   [clj-time "0.14.4"]
                                   [clojure-term-colors "0.1.0"]]}})
