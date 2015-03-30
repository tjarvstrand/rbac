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


(def role-permissions #{:read :update :delete})


(defn- get-resource [context id]
  (if-let [resource (context/get-resource context id)]
    resource
    (throw (ex-info (format    "Resource %s doesn't exist"
                               (string/join ":" id))
                    {:cause    :no-exists
                     :resource id}))))

(defn- get-role
  "Return role with id in context"
  [context id]
  (get-resource context ["roles" id]))

(defn- protected-resource?
  "Return truthy value iff resource-id is protected (cannot be deleted)."
  [resource-id]
  (some #{resource-id} [[] ["roles"] ["roles" "admin"]]))

(defn fixpoint
  "Calculate a fixpoint for fun with context.

Repeatedly applies fun to context until two consecutive calls yield the same
return value, then returns that value."
  [context fun initial]
  (let [new (fun context initial)]
    (if (= new initial)
      new
      (recur context fun new))))

(defn- expand-permissions
  "Expand permissions to recursively apply to all role members in context.

Permissions is a map role->#{permission}."
  [context permissions]
  (apply merge-with
         into
         permissions
         (for [[role-id role-perms] permissions
               :let [members (-> context (get-role role-id) :members)]]
           (zipmap members (repeat (count members) role-perms)))))


(defn- expand-roles
  "Recursively expand roles to include all role members in context."
  [context role-ids]
  (into role-ids (mapcat #(:members (get-role context %)) role-ids)))

(defn- resource-permission-fixpoint
  "Compute a fixpoint for resource-id's recursive permission set."
  [context resource-id]
  (update-in (get-resource context resource-id)
             [:permissions]
             #(fixpoint context expand-permissions %)))

(defn- resource-owners-fixpoint [context resource-id]
  "Compute a fixpoint for resource-id's recursive owners set."
  (fixpoint context
            expand-roles
            (:owners (get-resource context resource-id))))

(defn- resource-owner?
  "Return non-nil iff role-id is an owner of resource-id in context."
  [context resource-id role-id]
  (and (get-role context role-id)
       (contains? (resource-owners-fixpoint context resource-id) role-id)))

(defn- resource-permission?
  "Return non-nil iff role-id has permission on resource-id in context."
  [context resource-id permission role-id]
  (and (get-role context role-id)
       (some-> (resource-permission-fixpoint context resource-id)
               :permissions
               (get role-id)
               permission)))

(defn authorized? [context resource-id permission as-id]
  "Return non-nil iff role-id is authorized permission access on resource-id in
context."
  (get-role context as-id)
  (when-not (and (protected-resource? resource-id) (= :delete permission))
    (or (resource-owner? context resource-id as-id)
        (resource-permission? context resource-id permission as-id))))

(defn- assert-owner
  "Return iff role-id is an owner of resource id in context, otherwise throws
java.lang.ExceptionInfo with :cause :unauthorized."
  [context resource-id role-id]
  (if-not (resource-owner? context resource-id role-id)
    (throw (ex-info (format "Role %s is not the owner of %s"
                            role-id
                            resource-id)
                    {:cause     :unauthorized
                     :as        role-id
                     :resource  (string/join ":" resource-id)}))))

(defn- assert-authorized
  "Return iff as-id is is authorized permission on resource-id in context,
otherwise throws java.lang.ExceptionInfo with :cause :unauthorized."
  [context resource-id permission as-id]
  (if-not (authorized? context resource-id permission as-id)
    (throw (ex-info (format "Role %s does not have permission %s on %s"
                            as-id
                            permission
                            resource-id)
                    {:cause     :unauthorized
                     :action    permission
                     :as        as-id
                     :resource  (string/join ":" resource-id)}))))

(defn- assert-no-resource
  "Return iff there is no resource with id in context, otherwise throws
java.lang.ExceptionInfo with :cause :exists."
  [context id]
  (if (context/get-resource context id)
    (throw (ex-info (format    "Resource %s already exists" id)
                    {:cause    :exists
                     :resource id}))))

(defn- assert-role-permissions [permissions]
  "Return iff there is no resource with id in context, otherwise throws
java.lang.ExceptionInfo with :cause :exists."
  (when-let [illegal (not= #{} (set/difference (set permissions) role-permissions))]
    (throw (ex-info (format    "Illegal role permissions: %s" illegal)
                    {:cause    :invalid-permission
                     :resource illegal}))))

(defn assert-id
  "Return iff id is a valid resource identifier, otherwise throws
java.lang.ExceptionInfo with :cause :illegal-resource-id."
  [id]
  (when-not (and (sequential? id) (every? string? id))
    (throw (ex-info (format    "Illegal resource ID: %s" id)
                    {:cause    :illegal-resource-id
                     :resource id}))))

(defn create-resource [context id as-id]
  (assert-id id)
  (get-role context as-id) ;; assert that role exists
  (assert-authorized context (drop-last id) :create as-id)
  (assert-no-resource context id)
  (context/put-resource context (context/resource id #{as-id})))

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

(defn grant-resource-permissions [context on-id permissions to-id as-id]
  (assert-permissions permissions)
  (doseq [perm (conj permissions :update)]
    (assert-authorized context on-id perm as-id))
  (get-role context to-id) ;; assert that role exists
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

(defn grant-resource-ownership [context resource-id to-id as-id]
  (get-role context to-id) ;; assert that role exists
  (assert-owner context resource-id as-id)
  (let [resource (update-in (get-resource context resource-id)
                            [:owners]
                            #(conj %1 to-id))]
    (context/put-resource context resource)))

(defn revoke-resource-ownership [context resource-id from-id as-id]
  (assert-owner context resource-id as-id)
  (let [resource (update-in (get-resource context resource-id)
                            [:owners]
                            #(disj %1 from-id))]
    (when (= #{} (:owners resource))
      (throw (ex-info (str "Illegal operation - can't revoke the last "
                           "owner's ownership")
                      {:cause    :illegal-operation
                       :resource resource-id})))
    (context/put-resource context resource)))

(defn grant-resource-membership [context on-id to-id as-id]
  (get-role context to-id) ;; assert that resource exists
  (assert-authorized context on-id :update as-id)
  (let [resource (update-in (get-resource context on-id)
                            [:members]
                            #(set (conj %1 to-id)))]
    (context/put-resource context resource)))

(defn grant-role-membership [context on-id to-id as-id]
  (grant-resource-membership context ["roles" on-id] to-id as-id))
