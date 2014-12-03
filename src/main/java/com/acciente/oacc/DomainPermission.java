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

public final class DomainPermission implements Serializable {
   // constants for the important system permission names with pre-defined semantics
   private static final SysPermission SYSPERMISSION_SUPER_USER          = new SysPermission(-301, "*SUPER-USER");
   private static final SysPermission SYSPERMISSION_CREATE_CHILD_DOMAIN = new SysPermission(-302, "*CREATE-CHILD-DOMAIN");

   // constants for the important system permission names with pre-defined semantics
   public static final String SUPER_USER          = SYSPERMISSION_SUPER_USER.getPermissionName();
   public static final String CREATE_CHILD_DOMAIN = SYSPERMISSION_CREATE_CHILD_DOMAIN.getPermissionName();

   // permission data
   private final long    systemPermissionId;
   private final String  permissionName;
   private final boolean withGrant;
   private final int     inheritLevel;
   private final int     domainLevel;

   public static List<String> getSysPermissionNames() {
      return Arrays.asList(SUPER_USER, CREATE_CHILD_DOMAIN);
   }

   public static String getSysPermissionName(long systemPermissionId) {
      if (systemPermissionId == SYSPERMISSION_SUPER_USER.getSystemPermissionId()) {
         return SYSPERMISSION_SUPER_USER.getPermissionName();
      }
      else if (systemPermissionId == SYSPERMISSION_CREATE_CHILD_DOMAIN.getSystemPermissionId()) {
         return SYSPERMISSION_CREATE_CHILD_DOMAIN.getPermissionName();
      }
      else {
         throw new IllegalArgumentException("Invalid system permission ID: " + systemPermissionId);
      }
   }

   // simpler and preferred factories to create a domain permission

   public static DomainPermission getInstance(String sysPermissionName) {
      return new DomainPermission(sysPermissionName);
   }

   public static DomainPermission getInstance(String sysPermissionName, boolean withGrant) {
      return new DomainPermission(sysPermissionName, withGrant);
   }

   public static DomainPermission getInstance(String sysPermissionName,
                                              boolean withGrant,
                                              int inheritLevel,
                                              int domainLevel) {
      return new DomainPermission(sysPermissionName, withGrant, inheritLevel, domainLevel);
   }

   private DomainPermission(String sysPermissionName) {
      this(sysPermissionName, false, 0, 0);
   }

   private DomainPermission(String sysPermissionName, boolean withGrant) {
      this(sysPermissionName, withGrant, 0, 0);
   }

   // constructor used when creating domain permissions from a syspermission id (typically read from a db)

   private DomainPermission(String sysPermissionName, boolean withGrant, int inheritLevel, int domainLevel) {
      SysPermission sysPermission = getSysPermission(sysPermissionName);

      this.systemPermissionId = sysPermission.getSystemPermissionId();
      this.permissionName = sysPermission.getPermissionName();
      this.withGrant = withGrant;
      this.inheritLevel = inheritLevel;
      this.domainLevel = domainLevel;
   }

   public String getPermissionName() {
      return permissionName;
   }

   public boolean isWithGrant() {
      return withGrant;
   }

   public long getSystemPermissionId() {
      if (!isSystemPermission()) {
         throw new IllegalArgumentException("No system permission ID may be retrieved for user permission: " + permissionName + ", please check your code");
      }

      return systemPermissionId;
   }

   public boolean isSystemPermission() {
      return systemPermissionId != 0;
   }

   public int getInheritLevel() {
      return inheritLevel;
   }

   public int getDomainLevel() {
      return domainLevel;
   }

   // equals() and hashCode()

   @Override
   public boolean equals(Object other) {
      if (this == other) {
         return true;
      }
      if (other == null || getClass() != other.getClass()) {
         return false;
      }

      DomainPermission otherDomainPermission = (DomainPermission) other;

      if (withGrant != otherDomainPermission.withGrant) {
         return false;
      }
      if (!permissionName.equals(otherDomainPermission.permissionName)) {
         return false;
      }

      return true;
   }

   public boolean equalsIgnoreGrant(Object other) {
      if (this == other) {
         return true;
      }
      if (other == null || getClass() != other.getClass()) {
         return false;
      }

      DomainPermission otherDomainPermission = (DomainPermission) other;

      if (!permissionName.equals(otherDomainPermission.permissionName)) {
         return false;
      }

      return true;
   }

   public boolean isGrantableFrom(DomainPermission other) {
      if (other == null) {
         return false;
      }

      if (!other.isWithGrant()) {
         return false;
      }

      return permissionName.equals(other.permissionName);
   }

   @Override
   public int hashCode() {
      int result = permissionName.hashCode();
      result = 31 * result + (withGrant ? 1 : 0);
      return result;
   }

   public String toString() {
      if (isSystemPermission()) {
         return "DOMAIN:SYS:" + permissionName
               + (withGrant ? " /G" : "")
               + (inheritLevel != 0 ? " /I:" + inheritLevel : "")
               + (domainLevel != 0 ? " /D:" + domainLevel : "");
      }
      else {
         // USR: for user-defined
         return "DOMAIN:" + permissionName
               + (withGrant ? " /G" : "")
               + (inheritLevel != 0 ? " /I:" + inheritLevel : "")
               + (domainLevel != 0 ? " /D:" + domainLevel : "");
      }
   }

   // private static helper method

   private static SysPermission getSysPermission(String permissionName) {
      if (permissionName == null || permissionName.trim().isEmpty()) {
         throw new IllegalArgumentException("A system permission name is required");
      }

      permissionName = permissionName.trim();

      if (SYSPERMISSION_SUPER_USER.getPermissionName().equals(permissionName)) {
         return SYSPERMISSION_SUPER_USER;
      }
      else if (SYSPERMISSION_CREATE_CHILD_DOMAIN.getPermissionName().equals(permissionName)) {
         return SYSPERMISSION_CREATE_CHILD_DOMAIN;
      }
      else {
         throw new IllegalArgumentException("Invalid system permission name: " + permissionName);
      }
   }
}
