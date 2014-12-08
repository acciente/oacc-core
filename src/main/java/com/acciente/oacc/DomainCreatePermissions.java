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

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class DomainCreatePermissions {
   // constants for the important system permission names with pre-defined semantics
   private static final SysPermission SYSPERMISSION_CREATE = new SysPermission(-300, "*CREATE");
   // constants for the important system permission names with pre-defined semantics
   public static final  String        CREATE               = SYSPERMISSION_CREATE.getPermissionName();

   public static List<String> getSysPermissionNames() {
      return Arrays.asList(CREATE);
   }

   public static String getSysPermissionName(long systemPermissionId) {
      if (systemPermissionId == SYSPERMISSION_CREATE.getSystemPermissionId()) {
         return SYSPERMISSION_CREATE.getPermissionName();
      }
      else {
         throw new IllegalArgumentException("Invalid system permission ID: " + systemPermissionId);
      }
   }

   public static DomainCreatePermission getInstance(String sysPermissionName, boolean withGrant) {
      return new DomainCreatePermissionImpl(sysPermissionName, withGrant, 0);
   }

   public static DomainCreatePermission getInstance(String sysPermissionName) {
      return new DomainCreatePermissionImpl(sysPermissionName, false, 0);
   }

   public static DomainCreatePermission getInstance(String sysPermissionName, boolean withGrant, int inheritLevel) {
      return new DomainCreatePermissionImpl(sysPermissionName, withGrant, inheritLevel);
   }

   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission) {
      return new DomainCreatePermissionImpl(domainPostCreatePermission, false, 0);
   }

   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission, boolean withGrant) {
      return new DomainCreatePermissionImpl(domainPostCreatePermission, withGrant, 0);
   }

   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission, boolean withGrant, int inheritLevel) {
      return new DomainCreatePermissionImpl(domainPostCreatePermission, withGrant, inheritLevel);
   }

   private static class DomainCreatePermissionImpl implements DomainCreatePermission, Serializable{
      // permission data
      private final long             systemPermissionId;
      private final String           sysPermissionName;
      private final DomainPermission postCreateDomainPermission;
      private final boolean          withGrant;
      private final int              inheritLevel;

      private DomainCreatePermissionImpl(String sysPermissionName, boolean withGrant, int inheritLevel) {
         SysPermission sysPermission = getSysPermission(sysPermissionName);

         this.systemPermissionId = sysPermission.getSystemPermissionId();
         this.sysPermissionName = sysPermission.getPermissionName();
         this.postCreateDomainPermission = null;
         this.withGrant = withGrant;
         this.inheritLevel = inheritLevel;
      }

      private DomainCreatePermissionImpl(DomainPermission postCreateDomainPermission, boolean withGrant, int inheritLevel) {
         this.systemPermissionId = 0;
         this.sysPermissionName = null;
         this.postCreateDomainPermission = postCreateDomainPermission;
         this.withGrant = withGrant;
         this.inheritLevel = inheritLevel;
      }

      @Override
      public boolean isSystemPermission() {
         return systemPermissionId != 0;
      }

      @Override
      public String getSysPermissionName() {
         if (!isSystemPermission()) {
            throw new IllegalStateException(
                  "No system permission name may be retrieved for non-system domain create permission: " + this + ", please check your code");
         }

         return sysPermissionName;
      }

      @Override
      public long getSystemPermissionId() {
         if (!isSystemPermission()) {
            throw new IllegalStateException(
                  "No system permission ID may be retrieved for non-system domain create permission: " + this + ", please check your code");
         }
         return systemPermissionId;
      }

      @Override
      public DomainPermission getPostCreateDomainPermission() {
         if (isSystemPermission()) {
            throw new IllegalStateException(
                  "No post create domain permission may be retrieved for system domain create permission: " + this + ", please check your code");
         }
         return postCreateDomainPermission;
      }

      @Override
      public boolean isWithGrant() {
         return withGrant;
      }

      @Override
      public boolean isGrantableFrom(DomainCreatePermission other) {
         if (other == null) {
            return false;
         }

         if (!other.isWithGrant()) {
            return false;
         }

         if (this.isSystemPermission() != other.isSystemPermission()) {
            return false;
         }

         if (this.isSystemPermission()) {
            return this.systemPermissionId == other.getSystemPermissionId();
         }

         if (this.postCreateDomainPermission.isWithGrant() && !other.getPostCreateDomainPermission().isWithGrant()) {
            return false;
         }

         return this.postCreateDomainPermission.equalsIgnoreGrant(other.getPostCreateDomainPermission());
      }

      public int getInheritLevel() {
         return inheritLevel;
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) {
            return true;
         }
         if (other == null || getClass() != other.getClass()) {
            return false;
         }

         DomainCreatePermissionImpl otherDomainCreatePermission = (DomainCreatePermissionImpl) other;

         if (systemPermissionId != otherDomainCreatePermission.systemPermissionId) {
            return false;
         }
         if (withGrant != otherDomainCreatePermission.withGrant) {
            return false;
         }
         if (postCreateDomainPermission != null
             ? !postCreateDomainPermission.equals(otherDomainCreatePermission.postCreateDomainPermission)
             : otherDomainCreatePermission.postCreateDomainPermission != null) {
            return false;
         }
         if (sysPermissionName != null
             ? !sysPermissionName.equals(otherDomainCreatePermission.sysPermissionName)
             : otherDomainCreatePermission.sysPermissionName != null) {
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

         DomainCreatePermissionImpl otherDomainCreatePermission = (DomainCreatePermissionImpl) other;

         if (systemPermissionId != otherDomainCreatePermission.systemPermissionId) {
            return false;
         }

         if (postCreateDomainPermission != null
             ? !postCreateDomainPermission.equals(otherDomainCreatePermission.postCreateDomainPermission)
             : otherDomainCreatePermission.postCreateDomainPermission != null) {
            return false;
         }

         if (sysPermissionName != null
             ? !sysPermissionName.equals(otherDomainCreatePermission.sysPermissionName)
             : otherDomainCreatePermission.sysPermissionName != null) {
            return false;
         }

         return true;
      }

      @Override
      public int hashCode() {
         int result = (int) (systemPermissionId ^ (systemPermissionId >>> 32));
         result = 31 * result + (sysPermissionName != null ? sysPermissionName.hashCode() : 0);
         result = 31 * result + (postCreateDomainPermission != null ? postCreateDomainPermission.hashCode() : 0);
         result = 31 * result + (withGrant ? 1 : 0);
         return result;
      }

      @Override
      public String toString() {
         if (postCreateDomainPermission == null) {
            return "*CREATE[]"
                  + (withGrant ? " /G" : "")
                  + (inheritLevel != 0 ? " /I:" + inheritLevel : "");
         }
         else {
            return "*CREATE[" + postCreateDomainPermission.toString() + "]"
                  + (withGrant ? " /G" : "")
                  + (inheritLevel != 0 ? " /I:" + inheritLevel : "");
         }
      }

      // private static helper method to convert a sys permission name to a sys permission object

      private static SysPermission getSysPermission(String systemPermissionName) {
         if (systemPermissionName == null || systemPermissionName.trim().isEmpty()) {
            throw new IllegalArgumentException("A system permission name is required");
         }

         systemPermissionName = systemPermissionName.trim();

         if (SYSPERMISSION_CREATE.getPermissionName().equals(systemPermissionName)) {
            return SYSPERMISSION_CREATE;
         }
         else {
            throw new IllegalArgumentException("Invalid system permission name: " + systemPermissionName);
         }
      }
   }
}
