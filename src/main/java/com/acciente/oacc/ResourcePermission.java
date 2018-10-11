/*
 * Copyright 2009-2017, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc;

/**
 * The interface for the type of permission that represents and governs an action on a resource.
 * <p/>
 * A ResourcePermission is the type of permission used to grant an accessor resource access to
 * another resource. The kind of "access" that a resource permission represents is determined
 * by the application and is typically described in the permission name. In addition to such
 * application-defined resource permissions, OACC provides a set of pre-defined common "system"
 * resource permissions: *INHERIT, *IMPERSONATE, *RESET-CREDENTIALS, *DELETE and *QUERY.
 * <p/>
 * To create an instance of this class use {@link ResourcePermissions#getInstance(String)} or one
 * of its variants.
 */
public interface ResourcePermission {
   /**
    * Determines if this is system permission.
    *
    * @return true if this is a system permission, false otherwise.
    */
   boolean isSystemPermission();

   /**
    * Retrieves the permission name.
    *
    * @return the name of the permission.
    */
   String getPermissionName();

   /**
    * Retrieve the id of a system permission.
    * <p/>
    * Applications should not use this id, but refer to the system permission by name instead.
    * <p/>
    * Note that if this is not a system permission an exception is thrown.
    *
    * @return the internal id of the system permission. Applications should not use this id.
    * @throws IllegalStateException if this method is called on a non-system permission.
    */
   long getSystemPermissionId();

   /**
    * Retrieves the value of the "grant option".
    *
    * @return true if this permission includes the privilege to be granted to others, false otherwise.
    */
   boolean isWithGrantOption();

   /**
    * Determines if this permission can be granted by a grantor holding the specified other permission.
    *
    * @param other another permission to compare with
    * @return true if this permission can be granted by a holder of the specified other permission,
    *         false otherwise.
    */
   boolean isGrantableFrom(ResourcePermission other);

   /**
    * Compare this permission with the specified other permission for equality, but ignoring the grant option.
    *
    * @param other another permission to compare with
    * @return true if the specified other permission is equal to this permission ignoring the
    *         value of the {@link #isWithGrantOption()} property.
    */
   boolean equalsIgnoreGrantOption(Object other);

}
