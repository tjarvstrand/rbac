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

(ns rbac.core
  (:require [clojure.string :as string]
            [clojure.set    :as set]
            [rbac.context   :as context]))

(defn- get-resource [context id]
  (if-let [resource (context/get-resource context id)]
    resource
    (throw (ex-info (format    "Resource %s doesn't exist"
                               (string/join ":" id))
                    {:cause    :no-exists
                     :resource id}))))

(defn- protected-resource? [resource-id]
  (some #{resource-id} [[] ["roles"] ["roles" "admin"]]))

(defn authorized? [context resource-id permission as-id]
  (if (and (protected-resource? resource-id) (= :delete permission))
    false
    (let [role     (get-resource context ["roles" as-id])
          resource (get-resource context resource-id)]

      (if (= :give permission)
        (= as-id (:owner resource))
        (or (= (:owner resource) as-id)
            (some #{permission} (get-in resource [:permissions as-id])))))))

(defn- assert-authorized [context resource-id permission as-id]
  (if-not (authorized? context resource-id permission as-id)
    (throw (ex-info (format "Role %s does not have permission %s on %s"
                            as-id
                            permission
                            resource-id)
                    {:cause     :unauthorized
                     :action    permission
                     :as        as-id
                     :resource  (string/join ":" resource-id)}))))

(defn- assert-no-resource [context id]
  (if (context/get-resource context id)
    (throw (ex-info (format    "Resource %s already exists" id)
                    {:cause    :exists
                     :resource id}))))

(defn- assert-role-permissions [permissions]
  (let [legal #{:read :update :delete}]
    (if-let [illegal (not= #{} (set/difference (set permissions) legal))]
      (throw (ex-info (format    "Illegal role permissions: %s" illegal)
                      {:cause    :illegal-permissions})))))

(defn create-resource [context id as-id]
  (get-resource context ["roles" as-id]) ;; assert that role exists
  (assert-authorized context (drop-last id) :create as-id)
  (assert-no-resource context id)
  (context/put-resource context (context/resource id as-id)))

(defn create-role [context id as-id]
  (create-resource context ["roles" id] as-id))

(defn read-resource [context id as-id]
  (assert-authorized context id :read as-id)
  (get-resource context id))

(defn read-role [context id as-id]
  (read-resource context ["roles" id] as-id))

(defn delete-resource [context id as-id]
  (assert-authorized context id :delete as-id)
  (context/delete-resource context id))

(defn delete-role [context id as-id]
  (delete-resource context ["roles" id] as-id))

(defn- assert-permissions [permissions type]
  (case type
    :role (assert-role-permissions)
    :resource true))

(defn grant-resource-permissions [context on-id permissions to-id as-id]
  (doseq [perm (conj permissions :update)]
    (assert-authorized context on-id perm as-id))
  (get-resource context ["roles" to-id]) ;; assert that role exists
  (let [resource (update-in (get-resource context on-id)
                         [:permissions to-id]
                         #(set (into %1 permissions)))]
    (context/put-resource context resource)))

(defn grant-role-permissions [context on-id permissions to-id as-id]
  (grant-resource-permissions context ["roles" on-id] permissions to-id as-id))

(defn revoke-resource-permissions [context on-id permissions from-id as-id]
  (assert-authorized context on-id :update as-id)
  (let [resource (update-in (get-resource context on-id)
                            [:permissions on-id from-id]
                            #(set/difference %1 (set permissions)))]
    (context/put-resource context resource)))

(defn revoke-role-permissions [context on-id permissions to-id as-id]
  (revoke-resource-permissions context ["roles" on-id] permissions to-id as-id))

(defn give-resource [context resource-id to-id as-id]
  (get-resource context ["roles" to-id]) ;; assert that role exists
  (assert-authorized context resource-id :give as-id)
  (context/put-resource context
                        (assoc (get-resource context resource-id)
                               :owner
                               to-id)))
