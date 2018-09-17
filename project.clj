(defproject no.nsd/clj-jwt "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [buddy/buddy-core "1.5.0"]
                 [buddy/buddy-sign "3.0.0"]
                 [org.clojure/data.json "0.2.6"]
                 [org.clojure/algo.generic "0.1.3"]
                 [invetica/uri "0.5.0"]]
  :profiles {:test {:resource-paths ["test-resources"]
                    :dependencies [[org.clojure/test.check "0.9.0"]
                                   [clj-time "0.14.4"]
                                   [clojure-term-colors "0.1.0"]]}})
