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

public class DomainCreatePermission implements Serializable {
   // constants for the important system permission names with pre-defined semantics
   private static final SysPermission SYSPERMISSION_CREATE = new SysPermission(-300, "*CREATE");

   // constants for the important system permission names with pre-defined semantics
   public static final String CREATE = SYSPERMISSION_CREATE.getPermissionName();

   // permission data
   private final long             systemPermissionId;
   private final String           sysPermissionName;
   private final DomainPermission postCreateDomainPermission;
   private final boolean          withGrant;

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
      return new DomainCreatePermission(sysPermissionName, withGrant);
   }

   public static DomainCreatePermission getInstance(String sysPermissionName) {
      return new DomainCreatePermission(sysPermissionName, false);
   }

   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission) {
      return new DomainCreatePermission(domainPostCreatePermission, false);
   }

   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission, boolean withGrant) {
      return new DomainCreatePermission(domainPostCreatePermission, withGrant);
   }

   private DomainCreatePermission(String sysPermissionName, boolean withGrant) {
      SysPermission sysPermission = getSysPermission(sysPermissionName);

      this.systemPermissionId = sysPermission.getSystemPermissionId();
      this.sysPermissionName = sysPermission.getPermissionName();
      this.postCreateDomainPermission = null;
      this.withGrant = withGrant;
   }

   private DomainCreatePermission(DomainPermission postCreateDomainPermission, boolean withGrant) {
      this.systemPermissionId = 0;
      this.sysPermissionName = null;
      this.postCreateDomainPermission = postCreateDomainPermission;
      this.withGrant = withGrant;
   }

   public DomainPermission getPostCreateDomainPermission() {
      if (isSystemPermission()) {
         throw new IllegalArgumentException(
               "No post create domain permission may be retrieved for system domain create permission: " + this + ", please check your code");
      }
      return postCreateDomainPermission;
   }

   public String getSysPermissionName() {
      if (!isSystemPermission()) {
         throw new IllegalArgumentException(
               "No system permission name may be retrieved for non-system domain create permission: " + this + ", please check your code");
      }

      return sysPermissionName;
   }

   public long getSystemPermissionId() {
      if (!isSystemPermission()) {
         throw new IllegalArgumentException(
               "No system permission ID may be retrieved for non-system domain create permission: " + this + ", please check your code");
      }
      return systemPermissionId;
   }

   public boolean isSystemPermission() {
      return systemPermissionId != 0;
   }

   public boolean isWithGrant() {
      return withGrant;
   }

   public String toString() {
      if (postCreateDomainPermission == null) {
         return "*CREATE[" + (withGrant ? "] (G)" : "]");
      }
      else {
         return "*CREATE[" + postCreateDomainPermission.toString() + (withGrant ? "] (G)" : "]");
      }
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
   public boolean equals(Object other) {
      if (this == other) {
         return true;
      }
      if (other == null || getClass() != other.getClass()) {
         return false;
      }

      DomainCreatePermission otherDomainCreatePermission = (DomainCreatePermission) other;

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