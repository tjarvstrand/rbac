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

(ns tjarvstrand.rbac.core
  (:require [clojure.string           :as string]
            [clojure.set              :as set]
            [tjarvstrand.rbac.context :as context]))


(def all-role-permissions #{:read :update :delete :grant})

(defn- get-role [context id]
  (if-let [role (context/get-role context id)]
    role
    (throw (ex-info (format "Role %s doesn't exist" id)
                    {:cause :no-exists
                     :role   id}))))

(defn unauthorized-actions
  "Return a set of the permissions in actions that as-id is not allowed
to perform in the given context."
  [context resource-id actions as-id]
  (if (= (context/get-superuser-id context) as-id)
    #{}
    (-> context
        (get-role as-id)
        (get-in [:permissions resource-id])
        (#(set/difference actions %)))))

(defn authorized?
  "Return falsey value iff as-id is allowed to perform all actions in actions."
  [context resource-id action as-id]
  (= #{} (unauthorized-actions context resource-id #{action} as-id)))


(defn assert-authorized
  "Return iff as-id is is authorized permission on resource-id in context,
otherwise throws java.lang.ExceptionInfo with :cause :unauthorized."
  [context resource-id actions as-id]
  (let [unauthorized (unauthorized-actions context resource-id actions as-id)]
    (when-not (= #{} unauthorized)
      (throw (ex-info (format "Role %s does not have permission %s on %s"
                              as-id
                              actions
                              resource-id)
                      {:cause     :unauthorized
                       :actions    actions
                       :as        as-id
                       :resource  resource-id})))))

(defn- assert-no-role
  "Return iff there is no resource with id in context, otherwise throws
java.lang.ExceptionInfo with :cause :exists."
  [context id]
  (if (context/get-role context id)
    (throw (ex-info (format    "Role %s already exists" id)
                    {:cause    :exists
                     :role id}))))

(defn- add-permissions [context on-id permissions to-id]
  (if (= (context/get-superuser-id context) to-id)
    context
    (let [role (update-in (get-role context to-id)
                          [:permissions on-id]
                          #(set (into %1 permissions)))]
      (context/put-role context role))))

(defn- remove-permissions [context on-id permissions to-id]
  (if (= (context/get-superuser-id context) to-id)
    context
    (let [role (update-in (get-role context to-id)
                          [:permissions on-id]
                          #(set/difference % permissions))]
      (context/put-role context role))))

(defn create-role [context id as-id]
  (-> context
      (context/put-role (context/role id))
      (add-permissions ["roles" id] all-role-permissions as-id)))

(defn read-role [context id as-id]
  (assert-authorized context ["roles" id] :read as-id)
  (get-role context id))

(defn delete-role [context id as-id]
  (assert-authorized context ["roles" id] :delete as-id)
  (context/delete-role context id))

(defn grant-permissions [context on-id permissions to-id as-id]
  (assert-authorized context on-id (set (conj permissions :grant)) as-id)
  (assert-authorized context ["roles" to-id] #{:update} as-id)
  (add-permissions context on-id permissions to-id))

(defn revoke-permissions [context on-id permissions to-id as-id]
  (assert-authorized context ["roles" to-id] #{:update} as-id)
  (remove-permissions context on-id permissions to-id))

(defn grant-role-permissions [context on-id permissions to-id as-id]
  (grant-permissions context ["roles" on-id] permissions to-id as-id))

(defn revoke-role-permissions [context on-id permissions to-id as-id]
  (revoke-permissions context ["roles" on-id] permissions to-id as-id))

(defn grant-role [context role-id to-id as-id]
  (assert-authorized context role-id :grant as-id)
  (assert-authorized context to-id :update as-id)
  (let [role (update-in (get-role context role-id)
                            [:roles]
                            #(set (conj %1 to-id)))]
    (context/put-role context role)))

(defn revoke-role [context role-id from-id as-id]
  (assert-authorized context from-id #{:update} as-id)
  (let [role (update-in (get-role context role-id)
                            [:roles]
                            #(set (conj %1 from-id)))]
    (context/put-role context role)))

(defn list-roles [context as-id]
  (assert-authorized context "roles" #{:read} as-id)
  (set (context/list-roles context)))
