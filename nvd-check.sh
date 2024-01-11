#!/usr/bin/env bash

set -u

# https://github.com/rm-hull/nvd-clojure

clojure -Ttools install nvd-clojure/nvd-clojure '{:mvn/version "4.0.0"}' :as nvd

clojure -J-Dclojure.main.report=stderr \
        -J-Dorg.slf4j.simpleLogger.log.org.apache.commons=error \
        -Tnvd nvd.task/check \
        :classpath \""$(clojure -Spath)\"" \
        :config-filename \""nvd-clojure.edn\""

RETVAL="$?"

echo "Exit code from scan was: $RETVAL"

if [ "$RETVAL" != "0" ]; then
  echo "Opening check report browser..."
  xdg-open "$(pwd)/target/nvd/dependency-check-report.html"
else
  echo "No vulnerabilities found!"
fi
