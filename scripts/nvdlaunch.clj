(ns nvdlaunch
  (:require [babashka.process :as process]))

(def quote "\"")

(defn launch [_]
      (let [cp (:out (process/shell {:out :string} "clojure" "-Spath"))
            exit (:exit (try
                          (process/shell
                            "clojure"
                            "-T:nvd-internal"
                            ":classpath"
                            (str quote cp quote)
                            ":config-filename"
                            (str quote "nvd-clojure.edn" quote))
                          (catch Exception e
                            (if (and (map? (ex-data e))
                                     (contains? (ex-data e) :exit))
                              (ex-data e)
                              (do
                                (println "Exception occurred:" (ex-message e))
                                (println "Unexpected ex-data:" (ex-data e))
                                {:exit 154})))))]
           (println "NVD exited with code" exit)
           (System/exit exit)))
