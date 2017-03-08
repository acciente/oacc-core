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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class DomainPermissions {
   // constants for the important system permission names with pre-defined semantics
   private static final SysPermission SYSPERMISSION_SUPER_USER          = new SysPermission(-301, "*SUPER-USER");
   public static final  String        SUPER_USER                        = SYSPERMISSION_SUPER_USER.getPermissionName();
   private static final SysPermission SYSPERMISSION_CREATE_CHILD_DOMAIN = new SysPermission(-302, "*CREATE-CHILD-DOMAIN");
   public static final  String        CREATE_CHILD_DOMAIN               = SYSPERMISSION_CREATE_CHILD_DOMAIN.getPermissionName();
   private static final SysPermission SYSPERMISSION_DELETE              = new SysPermission(-303, "*DELETE");
   public static final  String        DELETE                            = SYSPERMISSION_DELETE.getPermissionName();

   private static final Map<String, SysPermission>              sysPermissionsByName;
   private static final Map<Long, String>                       sysPermissionNamesById;
   private static final List<String>                            sysPermissionNames;
   private static final ConcurrentMap<String, DomainPermission> grantablePermissionsByName;
   private static final ConcurrentMap<String, DomainPermission> ungrantablePermissionsByName;
   static {
      sysPermissionsByName = new HashMap<>();
      sysPermissionsByName.put(SUPER_USER, SYSPERMISSION_SUPER_USER);
      sysPermissionsByName.put(CREATE_CHILD_DOMAIN, SYSPERMISSION_CREATE_CHILD_DOMAIN);
      sysPermissionsByName.put(DELETE, SYSPERMISSION_DELETE);

      sysPermissionNamesById = new HashMap<>(sysPermissionsByName.size());
      for (SysPermission sysPermission : sysPermissionsByName.values()) {
         sysPermissionNamesById.put(sysPermission.getSystemPermissionId(), sysPermission.getPermissionName());
      }

      sysPermissionNames = Collections.unmodifiableList(new ArrayList<>(sysPermissionNamesById.values()));

      grantablePermissionsByName = new ConcurrentHashMap<>(sysPermissionsByName.size());
      ungrantablePermissionsByName = new ConcurrentHashMap<>(sysPermissionsByName.size());
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
    * Creates a new domain permission of the specified name, without
    * the option to grant the domain-permission to another resource
    *
    * @param sysPermissionName  the name of the system domain permission
    * @return a domain permission
    */
   public static DomainPermission getInstance(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      DomainPermission domainPermission = ungrantablePermissionsByName.get(sysPermissionName);

      if (domainPermission == null) {
         domainPermission = new DomainPermissionImpl(sysPermissionName, false);
         final DomainPermission cachedInstance = ungrantablePermissionsByName.putIfAbsent(sysPermissionName, domainPermission);
         if (cachedInstance != null) {
            domainPermission = cachedInstance;
         }
      }

      return domainPermission;
   }

   /**
    * Creates a new domain permission of the specified name, but with
    * the option to grant the domain-permission to another resource
    *
    * @param sysPermissionName  the name of the system domain permission
    * @return a domain permission
    */
   public static DomainPermission getInstanceWithGrantOption(String sysPermissionName) {
      sysPermissionName = getCanonicalSysPermissionName(sysPermissionName);

      DomainPermission domainPermission = grantablePermissionsByName.get(sysPermissionName);

      if (domainPermission == null) {
         domainPermission = new DomainPermissionImpl(sysPermissionName, true);
         final DomainPermission cachedInstance = grantablePermissionsByName.putIfAbsent(sysPermissionName, domainPermission);
         if (cachedInstance != null) {
            domainPermission = cachedInstance;
         }
      }

      return domainPermission;
   }

   /**
    * @deprecated as of v2.0.0-rc.5; use {@link #getInstanceWithGrantOption(String)} or {@link #getInstance(String)} instead.
    */
   @Deprecated
   public static DomainPermission getInstance(String sysPermissionName, boolean withGrant) {
      return new DomainPermissionImpl(sysPermissionName, withGrant);
   }

   public static DomainPermission getInstance(DomainPermission domainPermission) {
      if (domainPermission instanceof DomainPermissions.DomainPermissionImpl) {
         return domainPermission;
      }

      final DomainPermission verifiedPermission;

      if(domainPermission.isWithGrantOption()) {
         verifiedPermission = getInstanceWithGrantOption(domainPermission.getPermissionName());
      }
      else {
         verifiedPermission = getInstance(domainPermission.getPermissionName());
      }

      // validate system permission name and id matched
      if (verifiedPermission.getSystemPermissionId() != domainPermission.getSystemPermissionId()) {
         throw new IllegalArgumentException("Invalid system permission id for domain permission: " + domainPermission);
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

   static class DomainPermissionImpl implements DomainPermission, Serializable {
      private static final long serialVersionUID = 1L;

      // permission data
      private final long    systemPermissionId;
      private final String  permissionName;
      private final boolean withGrantOption;

      private DomainPermissionImpl(String sysPermissionName, boolean withGrantOption) {
         SysPermission sysPermission = getSysPermission(sysPermissionName);

         this.systemPermissionId = sysPermission.getSystemPermissionId();
         this.permissionName = sysPermission.getPermissionName();
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
      public boolean isGrantableFrom(DomainPermission other) {
         if (other == null) {
            return false;
         }

         if (!other.isWithGrantOption()) {
            return false;
         }

         return permissionName.equals(other.getPermissionName());
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

         DomainPermissionImpl otherDomainPermission = (DomainPermissionImpl) other;

         if (withGrantOption != otherDomainPermission.withGrantOption) {
            return false;
         }
         if (!permissionName.equals(otherDomainPermission.permissionName)) {
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

         DomainPermissionImpl otherDomainPermission = (DomainPermissionImpl) other;

         if (!permissionName.equals(otherDomainPermission.permissionName)) {
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
         return withGrantOption ? permissionName + " /G" : permissionName;
      }

      // private static helper method

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
