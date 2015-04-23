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
            [tjarvstrand.rbac.context :as ctx]))


(def all-role-permissions #{:read :update :delete :grant})

(defn- get-role [ctx id]
  (if-let [role (get-in ctx [:roles id])]
    role
    (throw (ex-info (format   "Role %s doesn't exist" id)
                    {:cause   :no-exists
                     :role    id
                     :context ctx}))))

(defn- update-role
  ([ctx role]    (update-role ctx role (:id role)))
  ([ctx role id] (assoc-in ctx [:roles id] role)))

(defn- update-in-role [ctx role-id keys update-fn]
  (update-role ctx (update-in (get-role ctx role-id) keys update-fn)))

(defn- put-role [ctx role]
  (assoc-in ctx [:roles (:id role)] role))

(defn unauthorized-actions
  "Return a set of the permissions in actions that as-id is not allowed
to perform in the given ctx."
  [ctx resource-id actions as-id]
  (if (= (:superadmin ctx) as-id)
    #{}
    (-> ctx
        (get-role as-id)
        (get-in [:permissions resource-id])
        (#(set/difference actions %)))))

(defn authorized?
  "Return falsey value iff as-id is allowed to perform all actions in actions."
  [ctx resource-id action as-id]
  (= #{} (unauthorized-actions ctx resource-id #{action} as-id)))


(defn assert-authorized
  "Return iff as-id is is authorized permission on resource-id in ctx,
otherwise throws java.lang.ExceptionInfo with :cause :unauthorized."
  [ctx resource-id actions as-id]
  (let [unauthorized (unauthorized-actions ctx resource-id actions as-id)]
    (when-not (= #{} unauthorized)
      (throw (ex-info (format "Role %s does not have permission %s on %s"
                              as-id
                              (string/join ", " actions)
                              resource-id)
                      {:cause     :unauthorized
                       :actions    actions
                       :as        as-id
                       :resource  resource-id
                       :context   ctx})))))

(defn- assert-no-role
  "Return iff there is no resource with id in ctx, otherwise throws
java.lang.ExceptionInfo with :cause :exists."
  [ctx id]
  (if (get-in ctx [:roles id])
    (throw (ex-info (format   "Role %s already exists" id)
                    {:cause   :exists
                     :role    id
                     :context ctx}))))

(defn put-permissions [ctx on-id permissions to-id]
  (if (= (:superadmin ctx) to-id)
    ctx
    (update-in-role ctx
                    to-id
                    [:permissions on-id]
                    #(set (into permissions %)))))

(defn- delete-permissions [ctx on-id permissions to-id]
  (if (= (:superadmin ctx) to-id)
    ctx
    (update-in-role ctx
                    to-id
                    [:permissions on-id]
                    #(do (println %) (set/difference % permissions)))))

(defn create-role [ctx id as-id]
  (assert-authorized ctx [:roles] #{:create} as-id)
  (-> ctx
      (put-role (ctx/role id))
      (put-permissions [:roles id] all-role-permissions as-id)))

(defn read-role [ctx id as-id]
  (assert-authorized ctx [:roles id] #{:read} as-id)
  (get-role ctx id))

(defn delete-role [ctx id as-id]
  (assert-authorized ctx [:roles id] #{:delete} as-id)
  (assoc-in ctx [:roles id] nil))

(defn grant-permissions [ctx on-id permissions to-id as-id]
  (assert-authorized ctx on-id (set (conj permissions :grant)) as-id)
  (assert-authorized ctx [:roles to-id] #{:update} as-id)
  (put-permissions ctx on-id permissions to-id))

(defn revoke-permissions [ctx on-id permissions to-id as-id]
  (assert-authorized ctx [:roles to-id] #{:update} as-id)
  (delete-permissions ctx on-id permissions to-id))

(defn grant-role-permissions [ctx on-id permissions to-id as-id]
  (grant-permissions ctx [:roles on-id] permissions to-id as-id))

(defn revoke-role-permissions [ctx on-id permissions to-id as-id]
  (revoke-permissions ctx [:roles on-id] permissions to-id as-id))

(defn grant-role [ctx role-id to-id as-id]
  (assert-authorized ctx role-id #{:grant} as-id)
  (assert-authorized ctx to-id :update as-id)
  (let [role (update-role ctx role-id #(set (conj %1 to-id)))]
    (put-role ctx role)))

(defn revoke-role [ctx role-id from-id as-id]
  (assert-authorized ctx from-id #{:update} as-id)
  (let [role (update-role ctx role-id #(set (conj %1 from-id)))]
    (put-role ctx role)))

(defn list-roles [ctx as-id]
  (assert-authorized ctx [:roles] #{:read} as-id)
  (sort (keys (:roles ctx))))
