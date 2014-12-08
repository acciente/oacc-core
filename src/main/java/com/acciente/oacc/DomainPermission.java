/*
 * Copyright 2009-2014, Acciente LLC
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
 * A DomainPermission is the type of permission used to grant an accessor permission to manage
 * a domain. A DomainPermission is always a system permission; the system permission values
 * supported are *SUPER-USER and *CREATE-CHILD-DOMAIN.
 * <p/>
 * To create an instance of this class use {@link DomainPermissions#getInstance(String)} or one
 * of its variants.
 */
public interface DomainPermission {
   /**
    * Property to determine if this is system permission.
    *
    * @return true if this is a system permission, false otherwise.
    */
   boolean isSystemPermission();

   /**
    * Property to retrieve the system permission name, if this is not a system permission an
    * exception is thrown.
    *
    * @return the name of the system permission.
    * @throws IllegalStateException if this method is called on a non-system permission.
    */
   String getPermissionName();

   /**
    * Property to retrieve the system permission id, if this is not a system permission an
    * exception is thrown.
    *
    * @return the internal id of the system permission. Applications should not use this id.
    * @throws IllegalStateException if this method is called on a non-system permission.
    */
   long getSystemPermissionId();

   /**
    * Property to retrieve the "with grant" option.
    *
    * @return true if this permission includes the privilege to grant, false otherwise.
    */
   boolean isWithGrant();

   /**
    * Used to determine if this permission can be granted by an grantor holding the specified
    * permission.
    *
    * @param other another permission to compare with
    * @return true if this permission can be granted by a holder of the passed in permission,
    *         false otherwise.
    */
   boolean isGrantableFrom(DomainPermission other);

   /**
    * Compare this permission with the specified permission ignoring the grant option.
    *
    * @param other another permission to compare with
    * @return true if the passed in permission is equal to this permission ignoring the
    *         value of the {@link #isWithGrant()} property.
    */
   boolean equalsIgnoreGrant(Object other);
}
