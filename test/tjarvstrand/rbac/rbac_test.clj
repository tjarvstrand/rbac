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

(defn- init-rbac []
  (-> (context/init (mock-context/new))
      (context/put-resource (context/resource ["roles" "alice"] #{"admin"}))
      (context/put-resource (context/resource ["roles" "bob"]   #{"admin"}))
      (context/put-resource (context/resource ["roles" "carol"] #{"admin"}))
      (context/put-resource (context/resource ["a"]             #{"admin"}))
      (context/put-resource (context/resource ["b"]             #{"admin"}))))

(fact "By default, admin has create, read, and update access on /"
  (authorized? (init-rbac) [] :create "admin") => truthy
  (authorized? (init-rbac) [] :read   "admin") => truthy
  (authorized? (init-rbac) [] :update "admin") => truthy
  (authorized? (init-rbac) [] :delete "admin") => falsey)

(fact "By default, alice has no access on the root level"
  (authorized? (init-rbac) [] :create "alice") => falsey
  (authorized? (init-rbac) [] :read   "alice") => falsey
  (authorized? (init-rbac) [] :update "alice") => falsey
  (authorized? (init-rbac) [] :delete "alice") => falsey)

(fact "By default alice can't create a resource under /"
  (create-resource (init-rbac) ["r"] "alice")
  => (throws clojure.lang.ExceptionInfo
             #(= :unauthorized (-> % ex-data :cause))))

(fact "A non-existing client can't perform any actions"
  (create-resource (init-rbac) ["a"] "chuck")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource))))

  (read-resource (init-rbac) ["a"] "chuck")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource))))

  (delete-resource (init-rbac) ["a"] "chuck")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource))))

  (grant-resource-permissions (init-rbac) ["a"] [:read] "alice" "chuck")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource))))

  (revoke-resource-permissions (init-rbac) ["a"] [:read] "alice" "chuck")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource)))))

(fact (str "A resource's owners can perform all actions on it even if not in "
           "permissions")
  (authorized? (init-rbac) ["a"] :create "admin") => truthy
  (authorized? (init-rbac) ["a"] :read   "admin") => truthy
  (authorized? (init-rbac) ["a"] :update "admin") => truthy
  (authorized? (init-rbac) ["a"] :delete "admin") => truthy)

(fact "It's not possible to create an existing resource"
  (create-resource (init-rbac) ["a"] "admin")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :exists (-> % ex-data :cause))
                   (= ["a"]   (-> % ex-data :resource)))))

(fact "When a resource is created, owners is correctly set"
  (:owners (context/get-resource (init-rbac) ["a"])) => #{"admin"})

(fact "A client can't grant permissions on non-existing resource"
  (grant-resource-permissions (init-rbac) ["c"] [:read] "alice" "admin")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists (-> % ex-data :cause))
                   (= ["c"]      (-> % ex-data :resource)))))

(fact "A client can't grant permissions on a resource to a non-existing role"
  (grant-resource-permissions (init-rbac) [] [:read] "chuck" "admin")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :no-exists        (-> % ex-data :cause))
                   (= ["roles" "chuck"] (-> % ex-data :resource)))))

(fact (str "A client can't grant permissions on a resource that it doesn't "
           "have itself")
  (grant-resource-permissions (init-rbac) [] [:delete] "alice" "admin")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "admin"       (-> % ex-data :as)))))

(fact "An unauthorized client can't perform any actions on resources"
  (read-resource (init-rbac) ["a"] "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as))))

  (create-resource (init-rbac) ["a"] "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as))))
  (delete-resource (init-rbac) ["a"] "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as))))
  (delete-resource (init-rbac) ["b"] "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as))))
  (grant-resource-permissions (init-rbac) [] [:read] "bob" "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))

(fact "A client with :update permission on a resource can grant its
permissions to other clients"
  (-> (init-rbac)
      (grant-resource-permissions [] [:create] "alice" "admin")
      (authorized? [] :create "alice"))
  => truthy)

(fact "A owning client can grant ownersship of a resource"
  (-> (init-rbac)
      (grant-resource-ownership ["a"] "alice" "admin")
      (read-resource ["a"] "alice")
      :owners)
      => #{"alice" "admin"})

(fact "A owning client can revoke ownersship of a resource"
  (-> (init-rbac)
      (grant-resource-ownership ["a"] "alice" "admin")
      (revoke-resource-ownership ["a"] "admin" "alice")
      (read-resource ["a"] "alice")
      :owners)
      => #{"alice"})

(fact "A resources last owner cannot have it's ownership revoked"
  (-> (init-rbac)
      (revoke-resource-ownership ["a"] "admin" "admin"))
  => (throws clojure.lang.ExceptionInfo
             #(and (= :illegal-operation (-> % ex-data :cause))
                   (= ["a"]              (-> % ex-data :resource)))))

(fact "No client with can give away another client's ownership of a
resource (not even with :update permission"
  (-> (init-rbac)
      (grant-resource-permissions ["a"] [:update] "alice" "admin")
      (grant-resource-ownership ["a"] "bob" "alice"))
      => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as)))))

(fact "Only valid resource names can be used"
  (create-resource (init-rbac) "foo" "admin")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :illegal-resource-id (-> % ex-data :cause))
                   (= "foo"                (-> % ex-data :resource)))))

(fact "Role memberships can be revoked")

 ;; TODO
(fact "When a role is deleted it is deleted as a an owner from all other resources")
(fact "When a resource is deleted it is deleted as a member from all other resources")
(fact "It's not possible to grant invalid permissions on a resource") ;; TODO


(fact "Role members can always read the role") ;; TODO

(fact "fixpoint works"
  (#'tjarvstrand.rbac.core/fixpoint nil #(if (>= %2 10) %2 (+ %2 1)) 1) => 10)

(fact "Resource permissions can be expanded"
  (-> (init-rbac)
      (grant-resource-permissions ["a"] [:read] "alice" "admin")
      (grant-role-membership "alice" "bob" "admin")
      (#'tjarvstrand.rbac.core/expand-permissions {"alice" #{:read}}))
      => {"alice" #{:read}, "bob" #{:read}})

(fact "Resource permission expansion fixpoint can be reached (resource
ownership is transitive)."
  (-> (init-rbac)
      (grant-resource-permissions ["a"] [:read] "alice" "admin")
      (grant-role-membership "alice" "bob" "admin")
      (grant-role-membership "bob" "carol" "admin")
      (#(#'tjarvstrand.rbac.core/resource-permission-fixpoint % ["a"]))
      :permissions)
      => {"alice" #{:read}, "bob" #{:read} "carol" #{:read}})

(fact "Role ownership can be expanded"
  (-> (init-rbac)
      (grant-role-membership "admin" "alice" "admin")
      (#'tjarvstrand.rbac.core/expand-roles #{"admin"}))
      => #{"alice" "admin"})

(fact "Resource permission expansion fixpoint can be reached (resource
permissions are transitive)."
  (-> (init-rbac)
      (grant-resource-ownership ["a"] "alice" "admin")
      (grant-role-membership "alice" "bob" "admin")
      (grant-role-membership "bob" "carol" "admin")
      (#(#'tjarvstrand.rbac.core/resource-owners-fixpoint % ["a"])))
      => #{"admin" "alice" "bob" "carol"})

