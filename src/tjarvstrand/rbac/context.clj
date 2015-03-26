;;
;; Copyright 2015 Thomas Järvstrand <tjarvstrand@gmail.com>
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;; http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns tjarvstrand.rbac.context
  (:require [clojure.string :as string]))

(def actions [:create :read :update :delete])

(defrecord Resource
    [id
     owner
     members
     permissions])

(defprotocol Context
  "Role Based Access Control"

  (put-resource [rbac resource]
    (str "Put resource into rbac, overwriting any existing Resource with the "
         "same id."))

  (get-resource [rbac id]
    "Return resource with id from rbac")

  (delete-resource [rbac id]
    "Delete resource with id from rbac"))

(defn resource [id owner]
  (map->Resource {:id id :owner owner :permissions {}}))

(defn init [rbac]
  (-> rbac
      (put-resource (resource []        "admin"))
      (put-resource (resource ["roles"] "admin"))
      (put-resource (resource ["roles" "admin"] "admin"))))
