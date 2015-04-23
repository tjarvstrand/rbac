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

(ns tjarvstrand.rbac.rbac-test
  (:use midje.sweet)
  (:require [tjarvstrand.rbac.core         :refer :all]
            [tjarvstrand.rbac.context      :as context]
            [tjarvstrand.rbac.mock-context :as mock-context]))

(def superadmin "superadmin")

(defn- init-rbac []
  (-> {:roles {} :superadmin superadmin}
      (create-role "alice" superadmin)
      (create-role "bob" superadmin)
      (create-role "carol" superadmin)))

(fact "superuser has full access."
  (authorized? (init-rbac) [] :create superadmin) => truthy
  (authorized? (init-rbac) [] :read   superadmin) => truthy
  (authorized? (init-rbac) [] :update superadmin) => truthy
  (authorized? (init-rbac) [] :delete superadmin) => truthy)

(fact "By default, alice has no access on the root level"
  (authorized? (init-rbac) [] :create "alice") => falsey
  (authorized? (init-rbac) [] :read   "alice") => falsey
  (authorized? (init-rbac) [] :update "alice") => falsey
  (authorized? (init-rbac) [] :delete "alice") => falsey)

(fact "Roles have no permissions on themselves, by default."
  (authorized? (init-rbac) ["roles" "alice"] :read   "alice") => falsey
  (authorized? (init-rbac) ["roles" "alice"] :update "alice") => falsey
  (authorized? (init-rbac) ["roles" "alice"] :grant  "alice") => falsey
  (authorized? (init-rbac) ["roles" "alice"] :delete "alice") => falsey
  (authorized? (init-rbac) ["roles" "alice"] :create "alice") => falsey)

(fact "A role can't grant permissions to a non-existing role"
  (grant-permissions (init-rbac) [] [:read] "chuck" superadmin)
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists (-> % ex-data :cause))
                   (= "chuck"    (-> % ex-data :role)))))

(fact "A role can't grant permissions that it doesn't have itself"
  (grant-permissions (init-rbac) [] #{:delete} "bob" "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))

(fact "A role without ;grant can't grant any permissions"
  (grant-permissions (init-rbac) [] [:read] "bob" "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))

(fact "A role with :grant permission can't grant its permissions to another role
 on which it doesn't have :update permission"
  (-> (init-rbac)
      (grant-permissions [] [:create :grant] "alice" superadmin)
      (grant-permissions [] #{:create}        "bob" "alice"))
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))


(fact "A role with :grant permission can grant its permissions to another role"
  (-> (init-rbac)
      (grant-permissions      [] #{:create :grant} "alice" superadmin)
      (grant-role-permissions "bob" #{:update}     "alice" superadmin)
      (grant-permissions      [] #{:create}        "bob" "alice")
      (authorized? [] :create "bob"))
  => truthy)

(fact "A role with :grant permission can't grant permissions it doesn't have"
  (-> (init-rbac)
      (grant-permissions [] [:grant] "alice" superadmin)
      (grant-permissions [] [:create] "bob" "alice")
      (authorized? [] :create "bob"))
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))

(fact "Role members are not given any permissions on the role by default"
  (-> (init-rbac)
      (grant-role "alice" "bob" superadmin)
      (authorized? "alice" :read "bob"))
      => falsey)

(fact "When a role is created the creator gains full permissions on it."
  (-> (init-rbac)
      (grant-permissions [:roles] #{:create} "alice" superadmin)
      (create-role "chuck" "alice")
      (unauthorized-actions [:roles "chuck"] all-role-permissions "alice"))
      => #{})

(fact "When a role is deleted and re-created it does not regain its permissions"
  (-> (init-rbac)
      (grant-permissions ["a"] #{:read} "alice" superadmin)
      (delete-role "alice" superadmin)
      (create-role "alice" superadmin)
      (authorized? ["a"] :read "alice")
      )
      => false)

(fact "Roles can be listed by a user with the correct permissions"
  (list-roles (init-rbac) superadmin) => '("alice" "bob" "carol"))
