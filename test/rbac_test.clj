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

(ns rbac-test
  (:use midje.sweet)
  (:require [rbac.core :refer :all]
            [rbac.context :as context]
            [rbac-mock])
  (:import  [rbac.context Role]))

(defn- init-rbac []
  (-> (context/init (rbac-mock/new))
      (context/put-role     (context/role "alice" "admin"))
      (context/put-role     (context/role "bob"   "admin"))
      (context/put-resource (context/resource "/a" "admin"))
      (context/put-resource (context/resource "/b" "admin"))))

(facts "about RBAC"

  (fact "By default, admin has create, read, and update access on /"
    (authorized? (init-rbac) "/" :create "admin") => truthy
    (authorized? (init-rbac) "/" :read   "admin") => truthy
    (authorized? (init-rbac) "/" :update "admin") => truthy
    (authorized? (init-rbac) "/" :delete "admin") => falsey)

  (fact "By default, alice has no access on the root level"
    (authorized? (init-rbac) "/" :create "alice") => falsey
    (authorized? (init-rbac) "/" :read   "alice") => falsey
    (authorized? (init-rbac) "/" :update "alice") => falsey
    (authorized? (init-rbac) "/" :delete "alice") => falsey)

  (fact "By default alice can't create a resource under /"
    (create-resource (init-rbac) "/r" "alice")
    => (throws clojure.lang.ExceptionInfo
               #(= :unauthorized (-> % ex-data :cause)))))

(facts "about non-existing clients"
  (fact "A non-existing client can't perform any actions"
    (create-resource (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol" (-> % ex-data :role))))

    (create-role (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role))))

    (read-resource (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol" (-> % ex-data :role))))

    (read-role (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role))))

    (delete-resource (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol" (-> % ex-data :role))))

    (delete-role (init-rbac) "/a" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role))))

    (grant-permissions (init-rbac) "/a" :resource [:read :create] "alice" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role))))

    (revoke-permissions (init-rbac) "/a" :resource [:read :create] "alice" "carol")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role))))
  ))

(facts "about roles"
  (fact "A role's owner can perform all actions on it even if not in permissions"
    ;; read
    (:id (read-role (init-rbac) "alice" "admin")) => "alice"
    ;; update
    (-> (init-rbac)
        (grant-role-permissions "bob" [:read] "alice" "admin")
        :roles
        (get "bob")
        :permissions
        (get "alice")
        :read) => :read

    ;; delete
    (record? (delete-role (init-rbac) "alice" "admin")) => true
    (-> (init-rbac)
        (delete-role "alice" "admin")
        (read-role "alice" "admin"))
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "alice"    (-> % ex-data :role)))))

  (fact "It's not possible to grant invalid permissions on a role") ;; TODO
  (fact "A client can give away its ownership of a role") ;; TODO
  (fact "Role members can always read the role")
  (fact (str "A client with :update permission cannot give away another "
             "client's ownership of a role")) ;; TODO

  (fact "An unauthorized client can't perform any actions on roles")
  (read-role (init-rbac) "bob" "alice")
  => (throws clojure.lang.ExceptionInfo
             #(and (= :unauthorized (-> % ex-data :cause))
                   (= "alice"       (-> % ex-data :as))))

  (fact "An unauthorized client can't read a role")
  (fact "An unauthorized client can't update a role")
  (fact "An unauthorized client can't delete a role")

  (fact "Role permissions are transitive"))

(facts "about resources"

  (fact "A resource's owner can perform all actions on it even if not in permissions"
    (authorized? (init-rbac) "/a" :create "admin") => truthy
    (authorized? (init-rbac) "/a" :read   "admin") => truthy
    (authorized? (init-rbac) "/a" :update "admin") => truthy
    (authorized? (init-rbac) "/a" :delete "admin") => truthy)

  (fact "It's not possible to create an existing resource"
    (create-resource (create-resource (init-rbac) "/r" "admin") "/r" "admin")
    => (throws clojure.lang.ExceptionInfo
               #(= :exists (-> % ex-data :cause))))

  (fact "When a resource is created, owner is correctly set"
    (:owner (context/get-resource (init-rbac) "/a")) => "admin")

  (fact (str "A client with :update permission on a resource can grant its "
             "permissions to other clients")
    (authorized? (grant-resource-permissions (init-rbac)
                                             "/"
                                             [:create]
                                             "alice"
                                             "admin")
                 "/"
                 :create
                 "alice")
    => truthy)

  (fact "A client can't grant permissions on a resource unless it has :update "
    "permission"
    (grant-resource-permissions (init-rbac) "/" [:read :create] "bob" "alice")
    => (throws clojure.lang.ExceptionInfo
               #(= :unauthorized (-> % ex-data :cause))))

  (fact "A client can't grant permissions on non-existing resource"
    (grant-resource-permissions (init-rbac)
                                "/c"
                                [:read :create]
                                "alice"
                                "admin")
    => (throws clojure.lang.ExceptionInfo
               #(= :no-exists (-> % ex-data :cause))))

  (fact "A client can't grant permissions on a resource to a non-existing role"
    (grant-resource-permissions (init-rbac) "/" [:read :create] "carol" "admin")
    => (throws clojure.lang.ExceptionInfo
               #(and (= :no-exists (-> % ex-data :cause))
                     (= "carol"    (-> % ex-data :role)))))

  (fact (str "A client can't grant permissions on a resource that it doesn't "
             "have itself")
    (grant-resource-permissions (init-rbac)  "/" [:delete] "alice" "admin")
    => (throws clojure.lang.ExceptionInfo
               #(= :unauthorized (-> % ex-data :cause))))

  (fact "it's not possible to create resources outside /")
  (fact "A client can give away its ownership of a resource") ;; TODO
  (fact (str "No client with can give away another client's ownership of a "
             "resource (not even with :update permission")) ;; TODO
  (fact "Resource permissions are transitive"))
