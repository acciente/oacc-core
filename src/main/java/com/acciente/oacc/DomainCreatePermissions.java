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

import com.acciente.oacc.DomainPermissions.DomainPermissionImpl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class DomainCreatePermissions {
   // constants for the important system permission names with pre-defined semantics
   private static final SysPermission SYSPERMISSION_CREATE = new SysPermission(-300, "*CREATE");
   public static final  String        CREATE               = SYSPERMISSION_CREATE.getPermissionName();

   private static final Map<String, SysPermission>                              sysPermissionsByName;
   private static final Map<Long, String>                                       sysPermissionNamesById;
   private static final List<String>                                            sysPermissionNames;
   private static final ConcurrentMap<String, DomainCreatePermission>           grantableCreatePermissionsByName;
   private static final ConcurrentMap<String, DomainCreatePermission>           ungrantableCreatePermissionsByName;
   private static final ConcurrentMap<DomainPermission, DomainCreatePermission> grantableCreatePermissionsByPostCreatePermission;
   private static final ConcurrentMap<DomainPermission, DomainCreatePermission> ungrantableCreatePermissionsByPostCreatePermission;
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
    * Creates a new domain create permission with no post-create permissions (i.e. only domain creation),
    * but with the option to grant the create-permission to another resource
    *
    * @param sysPermissionName  the name of the system permission
    * @return a domain create permission
    */
   public static DomainCreatePermission getInstanceWithGrantOption(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      DomainCreatePermission domainCreatePermission = grantableCreatePermissionsByName.get(sysPermissionName);

      if (domainCreatePermission == null) {
         domainCreatePermission = new DomainCreatePermissionImpl(sysPermissionName, true);
         final DomainCreatePermission cachedInstance
               = grantableCreatePermissionsByName.putIfAbsent(sysPermissionName, domainCreatePermission);
         if (cachedInstance != null) {
            domainCreatePermission = cachedInstance;
         }
      }

      return domainCreatePermission;
   }

   /**
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(String)} or {@link #getInstance(String)} instead.
    */
   @Deprecated
   public static DomainCreatePermission getInstance(String sysPermissionName, boolean withGrant) {
      return new DomainCreatePermissionImpl(sysPermissionName, withGrant);
   }

   /**
    * Creates a new domain create permission with no post-create permissions (i.e. only domain creation)
    * without the option to grant the create-permission to another resource
    *
    * @param sysPermissionName  the name of the system permission
    * @return a domain create permission
    */
   public static DomainCreatePermission getInstance(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      DomainCreatePermission domainCreatePermission = ungrantableCreatePermissionsByName.get(sysPermissionName);

      if (domainCreatePermission == null) {
         domainCreatePermission = new DomainCreatePermissionImpl(sysPermissionName, false);
         final DomainCreatePermission cachedInstance
               = ungrantableCreatePermissionsByName.putIfAbsent(sysPermissionName, domainCreatePermission);
         if (cachedInstance != null) {
            domainCreatePermission = cachedInstance;
         }
      }

      return domainCreatePermission;
   }

   /**
    * Creates a new domain create permission with the specified post-create domain permission
    * without the option to grant the create-permission to another resource
    *
    * @param postCreateDomainPermission  the post-create domain permission
    * @return a domain create permission
    */
   public static DomainCreatePermission getInstance(DomainPermission postCreateDomainPermission) {
      assertPostCreatePermissionSpecified(postCreateDomainPermission);
      // normalize post create permission before cache lookup, to prevent hash collisions from rogue implementations
      postCreateDomainPermission = DomainPermissions.getInstance(postCreateDomainPermission);

      DomainCreatePermission domainCreatePermission
            = ungrantableCreatePermissionsByPostCreatePermission.get(postCreateDomainPermission);

      if (domainCreatePermission == null) {
         domainCreatePermission = new DomainCreatePermissionImpl((DomainPermissionImpl) postCreateDomainPermission, false);
         final DomainCreatePermission cachedInstance
               = ungrantableCreatePermissionsByPostCreatePermission.putIfAbsent(postCreateDomainPermission, domainCreatePermission);
         if (cachedInstance != null) {
            domainCreatePermission = cachedInstance;
         }
      }

      return domainCreatePermission;
   }

   /**
    * Creates a new domain create permission with the specified post-create domain permission,
    * but with the option to grant the create-permission to another resource
    *
    * @param postCreateDomainPermission  the post-create domain permission
    * @return a domain create permission
    */
   public static DomainCreatePermission getInstanceWithGrantOption(DomainPermission postCreateDomainPermission) {
      assertPostCreatePermissionSpecified(postCreateDomainPermission);
      // normalize post create permission before cache lookup, to prevent hash collisions from rogue implementations
      postCreateDomainPermission = DomainPermissions.getInstance(postCreateDomainPermission);

      DomainCreatePermission domainCreatePermission
            = grantableCreatePermissionsByPostCreatePermission.get(postCreateDomainPermission);

      if (domainCreatePermission == null) {
         domainCreatePermission = new DomainCreatePermissionImpl((DomainPermissionImpl) postCreateDomainPermission, true);
         final DomainCreatePermission cachedInstance
               = grantableCreatePermissionsByPostCreatePermission.putIfAbsent(postCreateDomainPermission, domainCreatePermission);
         if (cachedInstance != null) {
            domainCreatePermission = cachedInstance;
         }
      }

      return domainCreatePermission;
   }

   /**
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(DomainPermission)} or {@link #getInstance(DomainPermission)} instead.
    */
   @Deprecated
   public static DomainCreatePermission getInstance(DomainPermission domainPostCreatePermission, boolean withGrant) {
      domainPostCreatePermission = DomainPermissions.getInstance(domainPostCreatePermission);
      return new DomainCreatePermissionImpl((DomainPermissionImpl) domainPostCreatePermission, withGrant);
   }

   public static DomainCreatePermission getInstance(DomainCreatePermission domainCreatePermission) {
      if (domainCreatePermission instanceof DomainCreatePermissions.DomainCreatePermissionImpl) {
         return domainCreatePermission;
      }

      final DomainCreatePermission verifiedPermission;

      if (domainCreatePermission.isSystemPermission()) {
         if (domainCreatePermission.isWithGrantOption()) {
            verifiedPermission = getInstanceWithGrantOption(domainCreatePermission.getPermissionName());
         }
         else {
            verifiedPermission = getInstance(domainCreatePermission.getPermissionName());
         }

         // validate system permission name and id matched
         if (verifiedPermission.getSystemPermissionId() != domainCreatePermission.getSystemPermissionId()){
            throw new IllegalArgumentException("Invalid system permission id for domain create permission: "
                                                     + domainCreatePermission);
         }
      }
      else {
         if (domainCreatePermission.isWithGrantOption()) {
            verifiedPermission = getInstanceWithGrantOption(DomainPermissions.getInstance(domainCreatePermission.getPostCreateDomainPermission()));
         }
         else {
            verifiedPermission = getInstance(DomainPermissions.getInstance(domainCreatePermission.getPostCreateDomainPermission()));
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

   private static void assertPostCreatePermissionSpecified(DomainPermission postCreateDomainPermission) {
      if (postCreateDomainPermission == null) {
         throw new IllegalArgumentException("A post create domain permission is required");
      }
   }

   static class DomainCreatePermissionImpl implements DomainCreatePermission, Serializable{
      private static final long serialVersionUID = 2L;

      // permission data
      private final long                 systemPermissionId;
      private final String               sysPermissionName;
      private final DomainPermissionImpl postCreateDomainPermission;
      private final boolean              withGrantOption;

      private DomainCreatePermissionImpl(String sysPermissionName,
                                         boolean withGrantOption) {
         SysPermission sysPermission = getSysPermission(sysPermissionName);

         this.systemPermissionId = sysPermission.getSystemPermissionId();
         this.sysPermissionName = sysPermission.getPermissionName();
         this.postCreateDomainPermission = null;
         this.withGrantOption = withGrantOption;
      }

      private DomainCreatePermissionImpl(DomainPermissionImpl postCreateDomainPermission,
                                         boolean withGrantOption) {
         this.systemPermissionId = 0;
         this.sysPermissionName = null;
         this.postCreateDomainPermission = postCreateDomainPermission;
         this.withGrantOption = withGrantOption;
      }

      @Override
      public boolean isSystemPermission() {
         return systemPermissionId != 0;
      }

      @Override
      public String getPermissionName() {
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
      public boolean isWithGrantOption() {
         return withGrantOption;
      }

      @Override
      @Deprecated
      public boolean isWithGrant() {
         return isWithGrantOption();
      }

      @Override
      public boolean isGrantableFrom(DomainCreatePermission other) {
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

         if (this.postCreateDomainPermission.isWithGrantOption() && !other.getPostCreateDomainPermission().isWithGrantOption()) {
            return false;
         }

         return this.postCreateDomainPermission.equalsIgnoreGrantOption(other.getPostCreateDomainPermission());
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
         if (withGrantOption != otherDomainCreatePermission.withGrantOption) {
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
      public boolean equalsIgnoreGrantOption(Object other) {
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
      @Deprecated
      public boolean equalsIgnoreGrant(Object other) {
         return equalsIgnoreGrantOption(other);
      }

      @Override
      public int hashCode() {
         int result = (int) (systemPermissionId ^ (systemPermissionId >>> 32));
         result = 31 * result + (sysPermissionName != null ? sysPermissionName.hashCode() : 0);
         result = 31 * result + (postCreateDomainPermission != null ? postCreateDomainPermission.hashCode() : 0);
         result = 31 * result + (withGrantOption ? 1 : 0);
         return result;
      }

      @Override
      public String toString() {
         if (postCreateDomainPermission == null) {
            return withGrantOption ? sysPermissionName + " /G" : sysPermissionName;
         }
         else {
            return "[" + postCreateDomainPermission.toString() + "]" + (withGrantOption ? " /G" : "");
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
