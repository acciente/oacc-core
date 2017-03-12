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

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestResourcePermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(ResourcePermissions.getSysPermissionNames().size(), is(5));
      assertThat(ResourcePermissions.getSysPermissionNames(), hasItem(ResourcePermissions.DELETE));
      assertThat(ResourcePermissions.getSysPermissionNames(), hasItem(ResourcePermissions.QUERY));
      assertThat(ResourcePermissions.getSysPermissionNames(), hasItem(ResourcePermissions.IMPERSONATE));
      assertThat(ResourcePermissions.getSysPermissionNames(), hasItem(ResourcePermissions.INHERIT));
      assertThat(ResourcePermissions.getSysPermissionNames(), hasItem(ResourcePermissions.RESET_CREDENTIALS));
   }

   @Test
   public void constructSystemPermission_valid() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstance(systemPermissionName);
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
         assertThat(resourcePermission.isSystemPermission(), is(true));
         assertThat(resourcePermission.isWithGrantOption(), is(false));
      }
   }

   @Test
   public void cacheSystemPermission_valid() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstance(systemPermissionName);
         assertThat(ResourcePermissions.getInstance(systemPermissionName), sameInstance(resourcePermission));
      }
   }

   @Test
   public void constructSystemPermission_withGrant_valid() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
         assertThat(resourcePermission.isSystemPermission(), is(true));
         assertThat(resourcePermission.isWithGrantOption(), is(true));
      }
   }

   @Test
   public void cacheSystemPermission_withGrant_valid() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(ResourcePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(resourcePermission));
      }
   }

   @Test
   public void constructCustomPermission_valid() {
      final String permissionName = "this_is_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(permissionName);
      assertThat(resourcePermission.getPermissionName(), is(permissionName));
      assertThat(resourcePermission.isSystemPermission(), is(false));
      assertThat(resourcePermission.isWithGrantOption(), is(false));
   }

   @Test
   public void cacheCustomPermission_valid() {
      final String permissionName = "this_is_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(permissionName);
      assertThat(ResourcePermissions.getInstance(permissionName), sameInstance(resourcePermission));
   }

   @Test
   public void constructCustomPermission_withGrant_valid() {
      final String permissionName = "this_is_also_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(permissionName);
      assertThat(resourcePermission.getPermissionName(), is(permissionName));
      assertThat(resourcePermission.isSystemPermission(), is(false));
      assertThat(resourcePermission.isWithGrantOption(), is(true));
   }

   @Test
   public void cacheCustomPermission_withGrant_valid() {
      final String permissionName = "this_is_also_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(permissionName);
      assertThat(ResourcePermissions.getInstanceWithGrantOption(permissionName), sameInstance(resourcePermission));
   }

   @Test
   public void constructSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
      }
      // now with grant
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(resourcePermission.getPermissionName(), is(systemPermissionName));
      }
   }

   @Test
   public void cacheSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(ResourcePermissions.getInstance(systemPermissionName), sameInstance(resourcePermission));
      }
      // now with grant
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(ResourcePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(resourcePermission));
      }
   }

   @Test
   public void constructCustomPermission_whitespaceConsistent() {
      final String permissionName = "this_is_a_valid_permission_name";

      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + permissionName + "\t");
      assertThat(resourcePermission.getPermissionName(), is(permissionName));

      // now with grant
      final ResourcePermission grantableResourcePermission = ResourcePermissions.getInstanceWithGrantOption(" " + permissionName + "\t");
      assertThat(grantableResourcePermission.getPermissionName(), is(permissionName));
   }

   @Test
   public void cacheCustomPermission_whitespaceConsistent() {
      final String permissionName = "this_is_a_valid_permission_name";

      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + permissionName + "\t");
      assertThat(ResourcePermissions.getInstance(permissionName), sameInstance(resourcePermission));

      // now with grant
      final ResourcePermission grantableResourcePermission = ResourcePermissions.getInstanceWithGrantOption(" " + permissionName + "\t");
      assertThat(ResourcePermissions.getInstanceWithGrantOption(permissionName), sameInstance(grantableResourcePermission));
   }

   @Test
   public void constructSystemPermission_caseSensitiveConsistent() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            ResourcePermissions.getInstance(mixedCasePermissionName);
            fail("permission names are case sensitive - creation of resource permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now with grant
         try {
            ResourcePermissions.getInstanceWithGrantOption(mixedCasePermissionName);
            fail("permission names are case sensitive - creation of resource permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void constructPermission_nulls_shouldFail() {
      try {
         ResourcePermissions.getInstance((String) null);
         fail("creation of resource permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         ResourcePermissions.getInstanceWithGrantOption(null);
         fail("creation of resource permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructPermission_emptyNames_shouldFail() {
      try {
         ResourcePermissions.getInstance("");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourcePermissions.getInstance(" \t");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         ResourcePermissions.getInstanceWithGrantOption("");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourcePermissions.getInstanceWithGrantOption(" \t");
         fail("creation of resource permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructSystemPermission_invalidSystemPermissionName_shouldFail() {
      try {
         ResourcePermissions.getInstance("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system resource permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now with grant
      try {
         ResourcePermissions.getInstanceWithGrantOption("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system resource permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void toString_systemPermission() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstance(systemPermissionName);
         assertThat(resourcePermission.toString(), is(systemPermissionName));
      }
   }

   @Test
   public void toString_systemPermission_withGrant() {
      for(String systemPermissionName : ResourcePermissions.getSysPermissionNames()) {
         final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(systemPermissionName);
         final String stringRepresentation = resourcePermission.toString();
         assertThat(stringRepresentation, is(systemPermissionName + " /G"));
      }
   }

   @Test
   public void toString_customPermission() {
      String customPermissionName = "myPermission";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(customPermissionName);
      assertThat(resourcePermission.toString(), is(customPermissionName));
   }

   @Test
   public void toString_customPermission_withGrant() {
      String customPermissionName = "myPermission";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(customPermissionName);
      final String stringRepresentation = resourcePermission.toString();
      assertThat(stringRepresentation, is(customPermissionName + " /G"));
   }
}
