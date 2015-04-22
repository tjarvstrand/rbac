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

(defrecord Role
    [id
     permissions
     roles])

(defprotocol Context
  "Role Based Access Control"

  (get-superuser-id [context]
    "Return the ID of the superuser")

  (put-role [context role]
    (str "Put role into context, overwriting any existing Role with the "
         "same id."))

  (get-role [context id]
    "Return role with id from context")

  (delete-role [context id]
    "Delete role with id from context")

  (list-roles [context]
    "Return the set of all role IDs"))

(defn role
  ([id]                   (role id {}))
  ([id permissions]       (role id {} #{}))
  ([id permissions roles] (map->Role {:id id
                                      :permissions permissions
                                      :roles roles})))
