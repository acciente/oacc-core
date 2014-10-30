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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestResourcePermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(ResourcePermission.getSysPermissionNames().size(), is(3));
      assertThat(ResourcePermission.getSysPermissionNames(), hasItem(ResourcePermission.IMPERSONATE));
      assertThat(ResourcePermission.getSysPermissionNames(), hasItem(ResourcePermission.INHERIT));
      assertThat(ResourcePermission.getSysPermissionNames(), hasItem(ResourcePermission.RESET_PASSWORD));
   }

   @Test
   public void constructSystemPermission_valid() throws AccessControlException {
      for(String systemPermissionName : ResourcePermission.getSysPermissionNames()) {
         ResourcePermission.getInstance(systemPermissionName);
      }
   }

   @Test
   public void constructSystemPermission_withGrant_valid() {
      for(String systemPermissionName : ResourcePermission.getSysPermissionNames()) {
         // with exception of *CREATE system permission, all should be creatable with grant option, as well
         ResourcePermission.getInstance(systemPermissionName, true);
      }
   }

   @Test
   public void constructCustomPermission_valid() throws AccessControlException {
      final String permissionName = "this_is_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermission.getInstance(permissionName);
      assertThat(resourcePermission.getPermissionName(), is(permissionName));
   }

   @Test
   public void constructCustomPermission_withGrant_valid() throws AccessControlException {
      final String permissionName = "this_is_also_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermission.getInstance(permissionName, true);
      assertThat(resourcePermission.getPermissionName(), is(permissionName));
   }

   @Test
   public void constructSystemPermission_whitespaceConsistent() throws AccessControlException {
      for(String systemPermissionName : ResourcePermission.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermission.getInstance(" " + systemPermissionName + "\t");
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
      }
      // now with grant
      for(String systemPermissionName : ResourcePermission.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermission.getInstance(" " + systemPermissionName + "\t", true);
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
      }
   }

   @Test
   public void constructCustomPermission_whitespaceConsistent() throws AccessControlException {
      final String permissionName = "this_is_a_valid_permission_name";

      final ResourcePermission resourcePermission = ResourcePermission.getInstance(" " + permissionName + "\t");
      assertThat(resourcePermission.getPermissionName(), is(permissionName));

      // now with grant
      final ResourcePermission grantableResourcePermission = ResourcePermission.getInstance(" " + permissionName + "\t", true);
      assertThat(grantableResourcePermission.getPermissionName(), is(permissionName));
   }

   @Test
   public void constructSystemPermission_caseSensitiveConsistent() throws AccessControlException {
      for(String systemPermissionName : ResourcePermission.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            ResourcePermission.getInstance(mixedCasePermissionName);
            fail("permission names are case sensitive - creation of resource permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now with grant
         try {
            ResourcePermission.getInstance(mixedCasePermissionName, true);
            fail("permission names are case sensitive - creation of resource permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void constructPermission_nulls_shouldFail() throws AccessControlException {
      try {
         ResourcePermission.getInstance(null);
         fail("creation of resource permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         ResourcePermission.getInstance(null, true);
         fail("creation of resource permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructPermission_emptyNames_shouldFail() throws AccessControlException {
      try {
         ResourcePermission.getInstance("");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourcePermission.getInstance(" \t");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         ResourcePermission.getInstance("", true);
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourcePermission.getInstance(" \t", true);
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructSystemPermission_invalidSystemPermissionName_shouldFail() throws AccessControlException {
      try {
         ResourcePermission.getInstance("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system resource permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now with grant
      try {
         ResourcePermission.getInstance("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk", true);
         fail("creating system resource permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }
}
