(defproject rbac "0.1.0-SNAPSHOT"
  :description "Role Based Access Control"
  :url "http://example.com/FIXME"
  :license {:name "Apache License, version 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.6.0"]]
  :profiles {:dev {:dependencies [[midje "1.6.3"]]
                   :plugins      [[lein-midje "3.1.3"]]
                   :source-paths ["dev"]
                   :repl-options {:init-ns user}}})
