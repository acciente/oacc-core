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
package com.acciente.reacc;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class ResourceCreatePermission implements Serializable {
   // constants for the important system permissions with pre-defined semantics
   private static final SysPermission SYSPERMISSION_CREATE = new SysPermission(-100, "*CREATE");

   // constants for the important system permissions with pre-defined semantics
   public static final String CREATE = SYSPERMISSION_CREATE.getPermissionName();

   // permission data
   private final long               systemPermissionId;
   private final String             sysPermissionName;
   private final ResourcePermission postCreateResourcePermission;
   private final boolean            withGrant;

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

   /**
    * Creates a new resource create permission with no post-create permissions (i.e. only resource creation)
    *
    * @param sysPermissionName
    * @param withGrant         true if the permission should have the grant privilege, false otherwise
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstance(String sysPermissionName, boolean withGrant) {
      return new ResourceCreatePermission(sysPermissionName, withGrant);
   }

   /**
    * Creates a new resource create permission with no post-create permissions (i.e. only resource creation)
    * and defaults the withGrant to false
    *
    * @param sysPermissionName
    * @return a resource create permission
    */
   public static ResourceCreatePermission getInstance(String sysPermissionName) {
      return new ResourceCreatePermission(sysPermissionName, false);
   }

   public static ResourceCreatePermission getInstance(ResourcePermission postCreateResourcePermission) {
      return new ResourceCreatePermission(postCreateResourcePermission, false);
   }

   public static ResourceCreatePermission getInstance(ResourcePermission postCreateResourcePermission,
                                                      boolean withGrant) {
      return new ResourceCreatePermission(postCreateResourcePermission, withGrant);
   }

   private ResourceCreatePermission(String sysPermissionName, boolean withGrant) {
      SysPermission sysPermission = getSysPermission(sysPermissionName);

      this.systemPermissionId = sysPermission.getSystemPermissionId();
      this.sysPermissionName = sysPermission.getPermissionName();
      this.postCreateResourcePermission = null;
      this.withGrant = withGrant;
   }

   private ResourceCreatePermission(ResourcePermission postCreateResourcePermission, boolean withGrant) {
      this.systemPermissionId = 0;
      this.sysPermissionName = null;
      this.postCreateResourcePermission = postCreateResourcePermission;
      this.withGrant = withGrant;
   }

   public ResourcePermission getPostCreateResourcePermission() {
      if (isSystemPermission()) {
         throw new IllegalArgumentException(
               "No post create resource permission may be retrieved for system resource create permission: " + this + ", please check your code");
      }
      return postCreateResourcePermission;
   }

   public String getSysPermissionName() {
      if (!isSystemPermission()) {
         throw new IllegalArgumentException(
               "No system permission name may be retrieved for non-system resource create permission: " + this + ", please check your code");
      }
      return sysPermissionName;
   }

   public long getSystemPermissionId() {
      if (!isSystemPermission()) {
         throw new IllegalArgumentException(
               "No system permission ID may be retrieved for non-system resource create permission: " + this + ", please check your code");
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
      if (postCreateResourcePermission == null) {
         return "*CREATE[" + (withGrant ? "] (grant)" : "]");
      }
      else {
         return "*CREATE[" + postCreateResourcePermission.toString() + (withGrant ? "] (grant)" : "]");
      }
   }

   @Override
   public int hashCode() {
      int result = (int) (systemPermissionId ^ (systemPermissionId >>> 32));
      result = 31 * result + (sysPermissionName != null ? sysPermissionName.hashCode() : 0);
      result = 31 * result + (postCreateResourcePermission != null ? postCreateResourcePermission.hashCode() : 0);
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

      ResourceCreatePermission otherResourceCreatePermission = (ResourceCreatePermission) other;

      if (systemPermissionId != otherResourceCreatePermission.systemPermissionId) {
         return false;
      }
      if (withGrant != otherResourceCreatePermission.withGrant) {
         return false;
      }
      if (postCreateResourcePermission != null
          ? !postCreateResourcePermission.equals(otherResourceCreatePermission.postCreateResourcePermission)
          : otherResourceCreatePermission.postCreateResourcePermission != null) {
         return false;
      }
      if (sysPermissionName != null
          ? !sysPermissionName.equals(otherResourceCreatePermission.sysPermissionName)
          : otherResourceCreatePermission.sysPermissionName != null) {
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
