/*
 * Copyright 2009-2015, Acciente LLC
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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ResourcePermissions {
   // constants for the important system permissions with pre-defined semantics
   private static final SysPermission SYSPERMISSION_INHERIT           = new SysPermission(-101, "*INHERIT");
   public static final  String        INHERIT                         = SYSPERMISSION_INHERIT.getPermissionName();
   private static final SysPermission SYSPERMISSION_IMPERSONATE       = new SysPermission(-102, "*IMPERSONATE");
   public static final  String        IMPERSONATE                     = SYSPERMISSION_IMPERSONATE.getPermissionName();
   private static final SysPermission SYSPERMISSION_RESET_CREDENTIALS = new SysPermission(-103, "*RESET-CREDENTIALS");
   public static final  String        RESET_CREDENTIALS               = SYSPERMISSION_RESET_CREDENTIALS.getPermissionName();
   private static final SysPermission SYSPERMISSION_DELETE            = new SysPermission(-104, "*DELETE");
   public static final  String        DELETE                          = SYSPERMISSION_DELETE.getPermissionName();
   private static final SysPermission SYSPERMISSION_QUERY             = new SysPermission(-105, "*QUERY");
   public static final  String        QUERY                           = SYSPERMISSION_QUERY.getPermissionName();

   private static final Map<String, SysPermission> sysPermissionsByName;
   private static final Map<Long, String>          sysPermissionNamesById;
   private static final List<String>               sysPermissionNames;
   static {
      sysPermissionsByName = new HashMap<>();
      sysPermissionsByName.put(INHERIT, SYSPERMISSION_INHERIT);
      sysPermissionsByName.put(IMPERSONATE, SYSPERMISSION_IMPERSONATE);
      sysPermissionsByName.put(RESET_CREDENTIALS, SYSPERMISSION_RESET_CREDENTIALS);
      sysPermissionsByName.put(DELETE, SYSPERMISSION_DELETE);
      sysPermissionsByName.put(QUERY, SYSPERMISSION_QUERY);

      sysPermissionNamesById = new HashMap<>(sysPermissionsByName.size());
      for (SysPermission sysPermission : sysPermissionsByName.values()) {
         sysPermissionNamesById.put(sysPermission.getSystemPermissionId(), sysPermission.getPermissionName());
      }

      sysPermissionNames = Collections.unmodifiableList(new ArrayList<>(sysPermissionNamesById.values()));
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

   public static ResourcePermission getInstance(String permissionName) {
      return new ResourcePermissionImpl(permissionName, false);
   }

   public static ResourcePermission getInstanceWithGrantOption(String permissionName) {
      return new ResourcePermissionImpl(permissionName, true);
   }

   /**
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(String)} or {@link #getInstance(String)} instead.
    */
   @Deprecated
   public static ResourcePermission getInstance(String permissionName, boolean withGrant) {
      return new ResourcePermissionImpl(permissionName, withGrant);
   }

   public static ResourcePermission getInstance(ResourcePermission resourcePermission) {
      if (resourcePermission instanceof ResourcePermissions.ResourcePermissionImpl) {
         return resourcePermission;
      }

      final ResourcePermission verifiedPermission;

      if (resourcePermission.isWithGrantOption()) {
         verifiedPermission = getInstanceWithGrantOption(resourcePermission.getPermissionName());
      }
      else {
         verifiedPermission = getInstance(resourcePermission.getPermissionName());
      }

      // validate system permission name and id matched
      if (resourcePermission.isSystemPermission() &&
            verifiedPermission.getSystemPermissionId() != resourcePermission.getSystemPermissionId()){
         throw new IllegalArgumentException("Invalid system permission id for resource permission: " + resourcePermission);
      }

      return verifiedPermission;
   }

   private static class ResourcePermissionImpl implements ResourcePermission, Serializable {
      // permission data
      private final long    systemPermissionId;
      private final String  permissionName;
      private final boolean withGrantOption;

      private ResourcePermissionImpl(String permissionName,
                                     boolean withGrantOption) {
         assertPermissionNameSpecified(permissionName);

         permissionName = permissionName.trim();

         if (permissionName.startsWith("*")) {
            SysPermission sysPermission = getSysPermission(permissionName);

            this.systemPermissionId = sysPermission.getSystemPermissionId();
            this.permissionName = sysPermission.getPermissionName();
         }
         else {
            this.systemPermissionId = 0;
            this.permissionName = permissionName.intern();
         }

         this.withGrantOption = withGrantOption;
      }

      @Override
      public boolean isSystemPermission() {
         return systemPermissionId != 0;
      }

      @Override
      public String getPermissionName() {
         return permissionName;
      }

      @Override
      public long getSystemPermissionId() {
         if (!isSystemPermission()) {
            throw new IllegalArgumentException("No system permission ID may be retrieved for user permission: " + permissionName + ", please check your code");
         }

         return systemPermissionId;
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
      public boolean isGrantableFrom(ResourcePermission other) {
         if (other == null) {
            return false;
         }

         if (!other.isWithGrantOption()) {
            return false;
         }

         return this.equalsIgnoreGrantOption(other);
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) {
            return true;
         }
         if (other == null || getClass() != other.getClass()) {
            return false;
         }

         ResourcePermissionImpl otherResourcePermission = (ResourcePermissionImpl) other;

         if (!permissionName.equals(otherResourcePermission.permissionName)) {
            return false;
         }
         if (withGrantOption != otherResourcePermission.withGrantOption) {
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

         ResourcePermissionImpl otherResourcePermission = (ResourcePermissionImpl) other;

         if (!permissionName.equals(otherResourcePermission.permissionName)) {
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
         int result = permissionName.hashCode();
         result = 31 * result + (withGrantOption ? 1 : 0);
         return result;
      }

      @Override
      public String toString() {
         return (isSystemPermission() ? "SYS:" + permissionName : permissionName)
               + (withGrantOption ? " /G" : "");
      }

      // private helper methods

      private void assertPermissionNameSpecified(String permissionName) {
         if (permissionName == null || permissionName.trim().isEmpty()) {
            throw new IllegalArgumentException("A permission name is required");
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
