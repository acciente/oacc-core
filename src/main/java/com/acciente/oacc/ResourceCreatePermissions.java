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

import com.acciente.oacc.ResourcePermissions.ResourcePermissionImpl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class ResourceCreatePermissions {
   // constants for the important system permissions with pre-defined semantics
   private static final SysPermission SYSPERMISSION_CREATE = new SysPermission(-100, "*CREATE");
   public static final  String        CREATE               = SYSPERMISSION_CREATE.getPermissionName();

   private static final Map<String, SysPermission>                                  sysPermissionsByName;
   private static final Map<Long, String>                                           sysPermissionNamesById;
   private static final List<String>                                                sysPermissionNames;
   private static final ConcurrentMap<String, ResourceCreatePermission>             grantableCreatePermissionsByName;
   private static final ConcurrentMap<String, ResourceCreatePermission>             ungrantableCreatePermissionsByName;
   private static final ConcurrentMap<ResourcePermission, ResourceCreatePermission> grantableCreatePermissionsByPostCreatePermission;
   private static final ConcurrentMap<ResourcePermission, ResourceCreatePermission> ungrantableCreatePermissionsByPostCreatePermission;

   static {
      sysPermissionsByName = new HashMap<>();
      sysPermissionsByName.put(CREATE, SYSPERMISSION_CREATE);

      sysPermissionNamesById = new HashMap<>(sysPermissionsByName.size());
      for (SysPermission sysPermission : sysPermissionsByName.values()) {
         sysPermissionNamesById.put(sysPermission.getSystemPermissionId(), sysPermission.getPermissionName());
      }

      sysPermissionNames = Collections.unmodifiableList(new ArrayList<>(sysPermissionNamesById.values()));

      grantableCreatePermissionsByName = new ConcurrentHashMap<>(sysPermissionsByName.size());
      ungrantableCreatePermissionsByName = new ConcurrentHashMap<>(sysPermissionsByName.size());
      grantableCreatePermissionsByPostCreatePermission = new ConcurrentHashMap<>();
      ungrantableCreatePermissionsByPostCreatePermission = new ConcurrentHashMap<>();
   }

   public static List<String> getSysPermissionNames() {
      return sysPermissionNames;
   }

   public static String getSysPermissionName(long systemPermissionId) {
      final String sysPermissionName = sysPermissionNamesById.get(systemPermissionId);

      if (sysPermissionName == null) {
         throw new IllegalArgumentException("Invalid system permission ID: " + systemPermissionId);
      }

      return sysPermissionName;
   }

   /**
    * Creates a new resource create permission with no post-create permissions (i.e. only resource creation),
    * but with the option to grant the create-permission to another resource
    *
    * @param sysPermissionName  the name of the system permission
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstanceWithGrantOption(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      ResourceCreatePermission resourceCreatePermission = grantableCreatePermissionsByName.get(sysPermissionName);

      if (resourceCreatePermission == null) {
         resourceCreatePermission = new ResourceCreatePermissionImpl(sysPermissionName, true);
         final ResourceCreatePermission cachedInstance
               = grantableCreatePermissionsByName.putIfAbsent(sysPermissionName, resourceCreatePermission);
         if (cachedInstance != null) {
            resourceCreatePermission = cachedInstance;
         }
      }

      return resourceCreatePermission;
   }

   /**
    * Creates a new resource create permission with no post-create permissions (i.e. only resource creation)
    *
    * @param sysPermissionName
    * @param withGrant         true if the permission should have the grant privilege, false otherwise
    * @return a resource create permission
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(String)} or {@link #getInstance(String)} instead.
    */
   @Deprecated
   public static ResourceCreatePermission getInstance(String sysPermissionName, boolean withGrant) {
      return new ResourceCreatePermissionImpl(sysPermissionName, withGrant);
   }


   /**
    * Creates a new resource create permission with no post-create permissions (i.e. only resource creation)
    * without the option to grant the create-permission to another resource
    *
    * @param sysPermissionName  the name of the system permission
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstance(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      ResourceCreatePermission resourceCreatePermission = ungrantableCreatePermissionsByName.get(sysPermissionName);

      if (resourceCreatePermission == null) {
         resourceCreatePermission = new ResourceCreatePermissionImpl(sysPermissionName, false);
         final ResourceCreatePermission cachedInstance
               = ungrantableCreatePermissionsByName.putIfAbsent(sysPermissionName, resourceCreatePermission);
         if (cachedInstance != null) {
            resourceCreatePermission = cachedInstance;
         }
      }

      return resourceCreatePermission;
   }

   /**
    * Creates a new resource create permission with the specified post-create permission
    * without the option to grant the create-permission to another resource
    *
    * @param postCreateResourcePermission  the post-create resource permission
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstance(ResourcePermission postCreateResourcePermission) {
      assertPostCreatePermissionSpecified(postCreateResourcePermission);
      // normalize post create permission before cache lookup, to prevent hash collisions from rogue implementations
      postCreateResourcePermission = ResourcePermissions.getInstance(postCreateResourcePermission);

      ResourceCreatePermission resourceCreatePermission
            = ungrantableCreatePermissionsByPostCreatePermission.get(postCreateResourcePermission);

      if (resourceCreatePermission == null) {
         resourceCreatePermission = new ResourceCreatePermissionImpl((ResourcePermissionImpl) postCreateResourcePermission, false);
         final ResourceCreatePermission cachedInstance
               = ungrantableCreatePermissionsByPostCreatePermission.putIfAbsent(postCreateResourcePermission, resourceCreatePermission);
         if (cachedInstance != null) {
            resourceCreatePermission = cachedInstance;
         }
      }

      return resourceCreatePermission;
   }

   /**
    * Creates a new resource create permission with the specified post-create permission,
    * but with the option to grant the create-permission to another resource
    *
    * @param postCreateResourcePermission  the post-create resource permission
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstanceWithGrantOption(ResourcePermission postCreateResourcePermission) {
      assertPostCreatePermissionSpecified(postCreateResourcePermission);
      // normalize post create permission before cache lookup, to prevent hash collisions from rogue implementations
      postCreateResourcePermission = ResourcePermissions.getInstance(postCreateResourcePermission);

      ResourceCreatePermission resourceCreatePermission
            = grantableCreatePermissionsByPostCreatePermission.get(postCreateResourcePermission);

      if (resourceCreatePermission == null) {
         resourceCreatePermission = new ResourceCreatePermissionImpl((ResourcePermissionImpl) postCreateResourcePermission, true);
         final ResourceCreatePermission cachedInstance
               = grantableCreatePermissionsByPostCreatePermission.putIfAbsent(postCreateResourcePermission, resourceCreatePermission);
         if (cachedInstance != null) {
            resourceCreatePermission = cachedInstance;
         }
      }

      return resourceCreatePermission;
   }

   /**
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(ResourcePermission)} or
    * {@link #getInstance(ResourcePermission)} instead.
    */
   @Deprecated
   public static ResourceCreatePermission getInstance(ResourcePermission postCreateResourcePermission,
                                                      boolean withGrant) {
      postCreateResourcePermission = ResourcePermissions.getInstance(postCreateResourcePermission);
      return new ResourceCreatePermissionImpl((ResourcePermissionImpl) postCreateResourcePermission, withGrant);
   }

   public static ResourceCreatePermission getInstance(ResourceCreatePermission resourceCreatePermission) {
      if (resourceCreatePermission instanceof ResourceCreatePermissions.ResourceCreatePermissionImpl) {
         return resourceCreatePermission;
      }

      final ResourceCreatePermission verifiedPermission;

      if (resourceCreatePermission.isSystemPermission()) {
         if (resourceCreatePermission.isWithGrantOption()) {
            verifiedPermission = getInstanceWithGrantOption(resourceCreatePermission.getPermissionName());
         }
         else {
            verifiedPermission = getInstance(resourceCreatePermission.getPermissionName());
         }

         // validate system permission name and id matched
         if (verifiedPermission.getSystemPermissionId() != resourceCreatePermission.getSystemPermissionId()) {
            throw new IllegalArgumentException("Invalid system permission id for resource create permission: "
                                                     + resourceCreatePermission);
         }
      }
      else {
         if (resourceCreatePermission.isWithGrantOption()) {
            verifiedPermission = getInstanceWithGrantOption(ResourcePermissions.getInstance(resourceCreatePermission
                                                                                    .getPostCreateResourcePermission()));
         }
         else {
            verifiedPermission = getInstance(ResourcePermissions.getInstance(resourceCreatePermission
                                                                                   .getPostCreateResourcePermission()));
         }
      }

      return verifiedPermission;
   }

   private static String getCanonicalSysPermissionName(String permissionName) {
      if (permissionName == null) {
         throw new IllegalArgumentException("A system permission name is required");
      }

      permissionName = permissionName.trim();

      if (permissionName.isEmpty()) {
         throw new IllegalArgumentException("A system permission name is required");
      }
      return permissionName;
   }

   private static void assertPostCreatePermissionSpecified(ResourcePermission postCreateResourcePermission) {
      if (postCreateResourcePermission == null) {
         throw new IllegalArgumentException("A post create resource permission is required");
      }
   }

   static class ResourceCreatePermissionImpl implements ResourceCreatePermission, Serializable {
      private static final long serialVersionUID = 2L;

      // permission data
      private final long                   systemPermissionId;
      private final String                 sysPermissionName;
      private final ResourcePermissionImpl postCreateResourcePermission;
      private final boolean                withGrantOption;

      private ResourceCreatePermissionImpl(String sysPermissionName,
                                           boolean withGrantOption) {
         SysPermission sysPermission = getSysPermission(sysPermissionName);

         this.systemPermissionId = sysPermission.getSystemPermissionId();
         this.sysPermissionName = sysPermission.getPermissionName();
         this.postCreateResourcePermission = null;
         this.withGrantOption = withGrantOption;
      }

      private ResourceCreatePermissionImpl(ResourcePermissionImpl postCreateResourcePermission,
                                           boolean withGrantOption) {
         this.systemPermissionId = 0;
         this.sysPermissionName = null;
         this.postCreateResourcePermission = postCreateResourcePermission;
         this.withGrantOption = withGrantOption;
      }

      @Override
      public boolean isSystemPermission() {
         return systemPermissionId != 0;
      }

      @Override
      public String getPermissionName() {
         if (!isSystemPermission()) {
            throw new IllegalArgumentException(
                  "No system permission name may be retrieved for non-system resource create permission: " + this + ", please check your code");
         }
         return sysPermissionName;
      }

      @Override
      public long getSystemPermissionId() {
         if (!isSystemPermission()) {
            throw new IllegalArgumentException(
                  "No system permission ID may be retrieved for non-system resource create permission: " + this + ", please check your code");
         }
         return systemPermissionId;
      }

      @Override
      public ResourcePermission getPostCreateResourcePermission() {
         if (isSystemPermission()) {
            throw new IllegalArgumentException(
                  "No post create resource permission may be retrieved for system resource create permission: " + this + ", please check your code");
         }
         return postCreateResourcePermission;
      }

      @Override
      public boolean isWithGrantOption() {
         return withGrantOption;
      }

      @Override
      @Deprecated
      public boolean isWithGrant() {
         return isWithGrantOption();
      }

      @Override
      public boolean isGrantableFrom(ResourceCreatePermission other) {
         if (other == null) {
            return false;
         }

         if (!other.isWithGrantOption()) {
            return false;
         }

         if (this.isSystemPermission() != other.isSystemPermission()) {
            return false;
         }

         if (this.isSystemPermission()) {
            return this.systemPermissionId == other.getSystemPermissionId();
         }

         if (this.postCreateResourcePermission.isWithGrantOption() && !other.getPostCreateResourcePermission().isWithGrantOption()) {
            return false;
         }

         return this.postCreateResourcePermission.equalsIgnoreGrantOption(other.getPostCreateResourcePermission());
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) {
            return true;
         }
         if (other == null || getClass() != other.getClass()) {
            return false;
         }

         ResourceCreatePermissionImpl otherResourceCreatePermission = (ResourceCreatePermissionImpl) other;

         if (systemPermissionId != otherResourceCreatePermission.systemPermissionId) {
            return false;
         }
         if (sysPermissionName != null
             ? !sysPermissionName.equals(otherResourceCreatePermission.sysPermissionName)
             : otherResourceCreatePermission.sysPermissionName != null) {
            return false;
         }
         if (postCreateResourcePermission != null
             ? !postCreateResourcePermission.equals(otherResourceCreatePermission.postCreateResourcePermission)
             : otherResourceCreatePermission.postCreateResourcePermission != null) {
            return false;
         }
         if (withGrantOption != otherResourceCreatePermission.withGrantOption) {
            return false;
         }

         return true;
      }

      @Override
      public boolean equalsIgnoreGrantOption(Object other) {
         if (this == other) {
            return true;
         }
         if (other == null || getClass() != other.getClass()) {
            return false;
         }

         ResourceCreatePermissionImpl otherResourceCreatePermission = (ResourceCreatePermissionImpl) other;

         if (systemPermissionId != otherResourceCreatePermission.systemPermissionId) {
            return false;
         }
         if (sysPermissionName != null
             ? !sysPermissionName.equals(otherResourceCreatePermission.sysPermissionName)
             : otherResourceCreatePermission.sysPermissionName != null) {
            return false;
         }
         if (postCreateResourcePermission != null
             ? !postCreateResourcePermission.equals(otherResourceCreatePermission.postCreateResourcePermission)
             : otherResourceCreatePermission.postCreateResourcePermission != null) {
            return false;
         }

         return true;
      }

      @Override
      @Deprecated
      public boolean equalsIgnoreGrant(Object other) {
         return equalsIgnoreGrantOption(other);
      }

      @Override
      public int hashCode() {
         int result = (int) (systemPermissionId ^ (systemPermissionId >>> 32));
         result = 31 * result + (sysPermissionName != null ? sysPermissionName.hashCode() : 0);
         result = 31 * result + (postCreateResourcePermission != null ? postCreateResourcePermission.hashCode() : 0);
         result = 31 * result + (withGrantOption ? 1 : 0);
         return result;
      }

      @Override
      public String toString() {
         if (postCreateResourcePermission == null) {
            return withGrantOption ? sysPermissionName + " /G" : sysPermissionName;
         }
         else {
            return "[" + postCreateResourcePermission.toString() + "]" + (withGrantOption ? " /G" : "");
         }
      }

      // private static helper method to convert a sys permission name to a sys permission object

      private static SysPermission getSysPermission(String permissionName) {
         if (permissionName == null) {
            throw new IllegalArgumentException("A system permission name is required");
         }

         final String trimmedPermissionName = permissionName.trim();

         if (trimmedPermissionName.isEmpty()) {
            throw new IllegalArgumentException("A system permission name is required");
         }

         final SysPermission sysPermission = sysPermissionsByName.get(trimmedPermissionName);

         if (sysPermission == null) {
            throw new IllegalArgumentException("Invalid system permission name: " + trimmedPermissionName);
         }

         return sysPermission;
      }
   }
}
