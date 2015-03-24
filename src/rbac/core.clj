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

(defn- resource-parent [id]
  (if-not (= id "/")
    (string/join (butlast (string/split id #"/")) "/")))

(defn- get-entry [context id type]
  (if-let [resource (case type
                          :resource (context/get-resource context id)
                          :role     (context/get-role context id))]
    resource
    (throw (ex-info (format "%s %s doesn't exist" (name type) id)
                    {:cause  :no-exists
                     type    id}))))

(defn- authorized-on-entry? [context entry-id entry-type permission as-id]
  (if (and (= :resource entry-type) (= "/" entry-id) (= :delete permission))
    false
    (let [role  (get-entry context as-id :role)
          entry (get-entry context entry-id entry-type)]
      (or (= (:owner entry) as-id)
          (some #{permission} (get-in entry [:permissions as-id]))))))

(defn authorized? [context resource-id permission as-id]
  (authorized-on-entry? context resource-id :resource permission as-id))

(defn- assert-authorized [context entry-id entry-type permission as-id]
  (if-not (and (string? entry-id)
               (authorized-on-entry? context
                                     entry-id
                                     entry-type
                                     permission as-id))
    (throw (ex-info (format "%s does not have permission %s on %s %s"
                            as-id
                            permission
                            (name entry-type)
                            entry-id)
                    {:cause  :unauthorized
                     :action permission
                     :as    as-id
                     entry-type entry-id}))))

(defn- assert-no-entry [context id type]
  (if (case type
        :resource (context/get-resource context id)
        :role     (context/get-role context id))
    (throw (ex-info (format    "%s %s already exists" (name type) id)
                    {:cause    :exists
                     type id}))))

(defn- assert-role-permissions [permissions]
  (let [legal #{:read :update :delete}]
    (if-let [illegal (not= #{} (set/difference (set permissions) legal))]
      (throw (ex-info (format    "Illegal role permissions: %s" illegal)
                      {:cause    :illegal-permissions})))))

(defn create-role
  [context id as-id]
  (get-entry context as-id :role) ;; assert that role exists
  (assert-no-entry context id :role)
  (context/put-role context (context/role id as-id)))

(defn create-resource
  [context id as-id]
  (assert-authorized context (resource-parent id) :resource :create as-id)
  (assert-no-entry context id :resource)
  (context/put-resource context (context/resource id as-id)))

(defn read-role
  [context id as-id]
  (assert-authorized context id :role :read as-id)
  (get-entry context id :role))

(defn read-resource
  [context id as-id]
  (assert-authorized context id :resource :read as-id)
  (get-entry context id :resource as-id))

(defn delete-role
  ([context id as-id]
   (assert-authorized context id :role :delete as-id)
   (context/delete-role context id)))

(defn delete-resource
  ([context id as-id]
   (assert-authorized context id :resource :delete as-id)
   (context/delete-resource context id)))

(defn- assert-permissions [permissions type]
  (case type
    :role (assert-role-permissions)
    :resource true))

(defn grant-permissions [context on-id on-type permissions to-id as-id]
  (assert-permissions permissions on-type)
  (get-entry context to-id :role) ;; assert that role exists
  (doseq [perm (conj permissions :update)]
    (assert-authorized context on-id on-type perm as-id))
  (let [entry (update-in (get-entry context on-id :resource)
                         [:permissions to-id]
                         #(set (into %1 permissions)))]
    (case type
      :role     (context/put-role context     entry)
      :resource (context/put-resource context entry))))

(defn revoke-permissions [context on-id on-type permissions from-id as-id]
  (assert-authorized context on-id on-type :update as-id)
  (if-let [entry (update-in (get-entry context on-id :resource)
                            [:permissions on-id from-id]
                            #(set/difference %1 (set permissions)))]
    (case type
      :role     (context/put-role context     entry)
      :resource (context/put-resource context entry))))
