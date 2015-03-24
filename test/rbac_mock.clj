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

(ns rbac-mock
  (:require [rbac.context]))

(defrecord RBAC [resources roles superuser-id]
    rbac.context/RBAC

    (put-resource [rbac resource]
      (assoc-in rbac [:resources (:id resource)] resource))

    (get-resource [rbac id]
      (get-in rbac [:resources id]))

    (delete-resource [rbac id]
      (assoc-in rbac [:resources id] nil)))

(defn new []
  (map->RBAC {:roles {}
              :resources {}}))


