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
import java.util.Arrays;
import java.util.List;

public class ResourcePermissions {
   // constants for the important system permissions with pre-defined semantics
   private static final SysPermission SYSPERMISSION_INHERIT           = new SysPermission(-101, "*INHERIT");
   public static final  String        INHERIT                         = SYSPERMISSION_INHERIT.getPermissionName();
   private static final SysPermission SYSPERMISSION_IMPERSONATE       = new SysPermission(-102, "*IMPERSONATE");
   public static final  String        IMPERSONATE                     = SYSPERMISSION_IMPERSONATE.getPermissionName();
   private static final SysPermission SYSPERMISSION_RESET_CREDENTIALS = new SysPermission(-103, "*RESET-CREDENTIALS");
   public static final  String        RESET_CREDENTIALS               = SYSPERMISSION_RESET_CREDENTIALS.getPermissionName();

   public static List<String> getSysPermissionNames() {
      return Arrays.asList(INHERIT, IMPERSONATE, RESET_CREDENTIALS);
   }

   public static String getSysPermissionName(long systemPermissionId) {
      if (systemPermissionId == SYSPERMISSION_INHERIT.getSystemPermissionId()) {
         return SYSPERMISSION_INHERIT.getPermissionName();
      }
      else if (systemPermissionId == SYSPERMISSION_IMPERSONATE.getSystemPermissionId()) {
         return SYSPERMISSION_IMPERSONATE.getPermissionName();
      }
      else if (systemPermissionId == SYSPERMISSION_RESET_CREDENTIALS.getSystemPermissionId()) {
         return SYSPERMISSION_RESET_CREDENTIALS.getPermissionName();
      }
      else {
         throw new IllegalArgumentException("Invalid system permission ID: " + systemPermissionId);
      }
   }

   public static ResourcePermission getInstance(String permissionName) {
      return new ResourcePermissionImpl(permissionName);
   }

   public static ResourcePermission getInstance(String permissionName, boolean withGrant) {
      return new ResourcePermissionImpl(permissionName, withGrant);
   }

   public static ResourcePermission getInstance(String permissionName,
                                                boolean withGrant,
                                                int inheritLevel,
                                                int domainLevel) {
      return new ResourcePermissionImpl(permissionName, withGrant, inheritLevel, domainLevel);
   }

   private static class ResourcePermissionImpl implements ResourcePermission, Serializable {
      // permission data
      private final long    systemPermissionId;
      private final String  permissionName;
      private final boolean withGrant;
      private final int     inheritLevel;
      private final int     domainLevel;

      private ResourcePermissionImpl(String permissionName) {
         this(permissionName, false, 0, 0);
      }

      private ResourcePermissionImpl(String permissionName, boolean withGrant) {
         this(permissionName, withGrant, 0, 0);
      }

      private ResourcePermissionImpl(String permissionName,
                                     boolean withGrant,
                                     int inheritLevel,
                                     int domainLevel) {
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

         this.withGrant = withGrant;
         this.inheritLevel = inheritLevel;
         this.domainLevel = domainLevel;
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
      public boolean isWithGrant() {
         return withGrant;
      }

      @Override
      public boolean isGrantableFrom(ResourcePermission other) {
         if (other == null) {
            return false;
         }

         if (!other.isWithGrant()) {
            return false;
         }

         return this.equalsIgnoreGrant(other);
      }

      public int getInheritLevel() {
         return inheritLevel;
      }

      public int getDomainLevel() {
         return domainLevel;
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
         if (withGrant != otherResourcePermission.withGrant) {
            return false;
         }

         return true;
      }

      @Override
      public boolean equalsIgnoreGrant(Object other) {
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
      public int hashCode() {
         int result = permissionName.hashCode();
         result = 31 * result + (withGrant ? 1 : 0);
         return result;
      }

      @Override
      public String toString() {
         return (isSystemPermission() ? "SYS:" + permissionName : permissionName)
               + (withGrant ? " /G" : "")
               + (inheritLevel != 0 ? " /I:" + inheritLevel : "")
               + (domainLevel != 0 ? " /D:" + domainLevel : "");
      }

      // private helper methods

      private void assertPermissionNameSpecified(String permissionName) {
         if (permissionName == null || permissionName.trim().isEmpty()) {
            throw new IllegalArgumentException("A permission name is required");
         }
      }

      // private static helper method to convert a sys permission name to a sys permission object

      private static SysPermission getSysPermission(String systemPermissionName) {
         if (systemPermissionName == null || systemPermissionName.trim().isEmpty()) {
            throw new IllegalArgumentException("A system permission name is required");
         }

         systemPermissionName = systemPermissionName.trim();

         if (SYSPERMISSION_INHERIT.getPermissionName().equals(systemPermissionName)) {
            return SYSPERMISSION_INHERIT;
         }
         else if (SYSPERMISSION_IMPERSONATE.getPermissionName().equals(systemPermissionName)) {
            return SYSPERMISSION_IMPERSONATE;
         }
         else if (SYSPERMISSION_RESET_CREDENTIALS.getPermissionName().equals(systemPermissionName)) {
            return SYSPERMISSION_RESET_CREDENTIALS;
         }
         else {
            throw new IllegalArgumentException("Invalid system permission name: " + systemPermissionName);
         }
      }
   }
}
