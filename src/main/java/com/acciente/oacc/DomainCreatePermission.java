/*
 * Copyright 2009-2018, Acciente LLC
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
 * The interface for a permission that governs creation of a domain and defines which permissions
 * the creator will receive on the new domain.
 * <p/>
 * A DomainCreatePermission is the type of permission used to grant a resource permission to
 * create domains. This permission type is also used to grant the creator resource the domain permissions
 * the creator will receive on the newly created domain (these are called post-create permissions).
 * The use of post-create permissions is optional. Post-create permissions should only be used
 * when other more manageable means, such as the global permissions mechanism, are not adequate
 * to grant the creator permissions on newly created domains.
 * <p/>
 * A DomainCreatePermission without post-create permission has to be a system permission. The only
 * system permission available for DomainCreatePermissions is the *CREATE system permission.
 * The *CREATE permission allows the accessor to create domains. As mentioned previously, a resource
 * with the *CREATE permission may also be granted post-create permissions to specify what permissions
 * it will receive on a domain it creates. Having the *CREATE permission is a pre-requisite
 * for having post-create permissions.
 * <p/>
 * To create an instance of this class use {@link DomainCreatePermissions#getInstance(String)}
 * or one of its variants.
 */
public interface DomainCreatePermission {
   /**
    * Determines if this is system permission.
    *
    * @return true if this is a system permission, false otherwise.
    */
   boolean isSystemPermission();

   /**
    * Retrieves the permission name.
    *
    * @return the name of the system permission.
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
    * Retrieves the post-create permission for non-system permissions.
    * <p/>
    * Note that if this is a system permission an exception is thrown.
    *
    * @return the post create resource permission associated with this permission.
    * @throws IllegalStateException if this method is called on a system permission.
    */
   DomainPermission getPostCreateDomainPermission();

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
   boolean isGrantableFrom(DomainCreatePermission other);

   /**
    * Compare this permission with the specified other permission for equality, but ignoring the grant option.
    *
    * @param other another permission to compare with
    * @return true if the specified other permission is equal to this permission ignoring the
    *         value of the {@link #isWithGrantOption()} property.
    */
   boolean equalsIgnoreGrantOption(Object other);

}
