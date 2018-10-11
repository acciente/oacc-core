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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestResourceCreatePermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(ResourceCreatePermissions.getSysPermissionNames().size(), is(1));
      assertThat(ResourceCreatePermissions.getSysPermissionNames(), hasItem(ResourceCreatePermissions.CREATE));
   }

   @Test
   public void constructSystemPermission_valid() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(systemPermissionName);
         assertThat(resourceCreatePermission.getPermissionName(), is(systemPermissionName));
         assertThat(resourceCreatePermission.isSystemPermission(), is(true));
         assertThat(resourceCreatePermission.isWithGrantOption(), is(false));
      }
   }

   @Test
   public void cacheSystemPermission_valid() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(systemPermissionName);
         assertThat(ResourceCreatePermissions.getInstance(systemPermissionName), sameInstance(resourceCreatePermission));
      }
   }

   @Test
   public void constructSystemPermission_withGrant_valid() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(resourceCreatePermission.getPermissionName(), is(systemPermissionName));
         assertThat(resourceCreatePermission.isSystemPermission(), is(true));
         assertThat(resourceCreatePermission.isWithGrantOption(), is(true));
      }
   }

   @Test
   public void cacheSystemPermission_withGrant_valid() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(ResourceCreatePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(resourceCreatePermission));
      }
   }

   @Test
   public void constructCustomPermission_valid() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(resourcePermission);
      assertThat(resourceCreatePermission.getPostCreateResourcePermission(), is(resourcePermission));
      assertThat(resourceCreatePermission.isSystemPermission(), is(false));
      assertThat(resourceCreatePermission.isWithGrantOption(), is(false));
   }

   @Test
   public void cacheCustomPermission_valid() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.DELETE)),
                 sameInstance(resourceCreatePermission));
   }

   @Test
   public void constructCustomPermission_withGrant_valid() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission);
      assertThat(resourceCreatePermission.getPostCreateResourcePermission(), is(resourcePermission));
      assertThat(resourceCreatePermission.isSystemPermission(), is(false));
      assertThat(resourceCreatePermission.isWithGrantOption(), is(true));
   }

   @Test
   public void cacheCustomPermission_withGrant_valid() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(ResourcePermissions.DELETE)),
                 sameInstance(resourceCreatePermission));
   }

   @Test
   public void constructSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(resourceCreatePermission.getPermissionName(), is(systemPermissionName));
      }
      // now with grant
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(resourceCreatePermission.getPermissionName(), is(systemPermissionName));
      }
   }

   @Test
   public void cacheSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(ResourceCreatePermissions.getInstance(systemPermissionName), sameInstance(resourceCreatePermission));
      }
      // now with grant
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission
               = ResourceCreatePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(ResourceCreatePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(resourceCreatePermission));
      }
   }

   @Test
   public void constructCustomPermission_whitespaceConsistent() {
      final String permissionName = "this_is_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + permissionName + "\t");

      final ResourceCreatePermission resourceCreatePermission
            = ResourceCreatePermissions.getInstance(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName)),
                 is(resourceCreatePermission));

      // now with grant
      final ResourceCreatePermission grantableResourceCreatePermission
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(permissionName)),
                 is(grantableResourceCreatePermission));
   }

   @Test
   public void cacheCustomPermission_whitespaceConsistent() {
      final String permissionName = "this_is_a_valid_permission_name";
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(" " + permissionName + "\t");

      final ResourceCreatePermission resourceCreatePermission
            = ResourceCreatePermissions.getInstance(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName)),
                 sameInstance(resourceCreatePermission));

      // now with grant
      final ResourceCreatePermission grantableResourceCreatePermission
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission);
      assertThat(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(permissionName)),
                 sameInstance(grantableResourceCreatePermission));
   }

   @Test
   public void constructSystemPermission_caseSensitiveConsistent() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            ResourceCreatePermissions.getInstance(mixedCasePermissionName);
            fail("system permission names are case sensitive - creation of resource create permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now with grant
         try {
            ResourceCreatePermissions.getInstanceWithGrantOption(mixedCasePermissionName);
            fail("system permission names are case sensitive - creation of resource permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void constructPermission_nulls_shouldFail() {
      try {
         ResourceCreatePermissions.getInstance((String) null);
         fail("creation of resource create permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourceCreatePermissions.getInstance((ResourcePermission) null);
         fail("creation of resource create permission with null post-create permission should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("post create resource permission is required"));
      }
      // now with grant
      try {
         ResourceCreatePermissions.getInstanceWithGrantOption((String) null);
         fail("creation of resource create permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourceCreatePermissions.getInstanceWithGrantOption((ResourcePermission) null);
         fail("creation of resource create permission with null post-create permission should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("post create resource permission is required"));
      }
   }

   @Test
   public void constructPermission_emptyNames_shouldFail() {
      try {
         ResourceCreatePermissions.getInstance("");
         fail("creation of resource create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourceCreatePermissions.getInstance(" \t");
         fail("creation of resource create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         ResourceCreatePermissions.getInstanceWithGrantOption("");
         fail("creation of resource create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         ResourceCreatePermissions.getInstanceWithGrantOption(" \t");
         fail("creation of resource create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructSystemPermission_invalidSystemPermissionName_shouldFail() {
      try {
         ResourceCreatePermissions.getInstance("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system resource create permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now with grant
      try {
         ResourceCreatePermissions.getInstanceWithGrantOption("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system resource create permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void serialize_internalPermissionImpl_shouldSucceed() throws IOException {
      final ResourcePermission serializablePermission = ResourcePermissions.getInstance("serializable_permission");
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(serializablePermission);

      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(resourceCreatePermission);
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void serialize_customPermissionImpl_shouldSucceed() throws IOException {
      final ResourcePermission nonSerializablePermission = new ResourcePermission() {
         @Override
         public boolean isSystemPermission() { return false; }

         @Override
         public String getPermissionName() { return "nonSerializable_permission"; }

         @Override
         public long getSystemPermissionId() { return 0; }

         @Override
         public boolean isWithGrantOption() { return false; }

         @Override
         public boolean isGrantableFrom(ResourcePermission other) { return false; }

         @Override
         public boolean equalsIgnoreGrantOption(Object other) { return false; }

      };

      final ResourceCreatePermission resourceCreatePermission
            = ResourceCreatePermissions.getInstance(nonSerializablePermission);

      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(resourceCreatePermission);
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void toString_systemPermission() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(systemPermissionName);
         assertThat(resourceCreatePermission.toString(), is(systemPermissionName));
      }
   }

   @Test
   public void toString_systemPermission_withGrant() {
      for(String systemPermissionName : ResourceCreatePermissions.getSysPermissionNames()) {
         final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         final String stringRepresentation = resourceCreatePermission.toString();
         assertThat(stringRepresentation, is(systemPermissionName + " /G"));
      }
   }

   @Test
   public void toString_customPermission() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstance(resourcePermission);
      final String stringRepresentation = resourceCreatePermission.toString();
      assertThat(stringRepresentation, is("[" + ResourcePermissions.DELETE + "]"));
   }

   @Test
   public void toString_customPermission_withGrant() {
      final ResourcePermission resourcePermission = ResourcePermissions.getInstance(ResourcePermissions.DELETE);
      final ResourceCreatePermission resourceCreatePermission = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission);
      final String stringRepresentation = resourceCreatePermission.toString();
      assertThat(stringRepresentation, is("[" + ResourcePermissions.DELETE + "] /G"));
   }
}
