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
import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestDomainCreatePermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(DomainCreatePermissions.getSysPermissionNames().size(), is(1));
      assertThat(DomainCreatePermissions.getSysPermissionNames(), hasItem(DomainCreatePermissions.CREATE));
   }

   @Test
   public void constructSystemPermission_valid() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(systemPermissionName);
         assertThat(domainCreatePermission.getPermissionName(), is(systemPermissionName));
         assertThat(domainCreatePermission.isSystemPermission(), is(true));
         assertThat(domainCreatePermission.isWithGrantOption(), is(false));
      }
   }

   @Test
   public void cacheSystemPermission_valid() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(systemPermissionName);
         assertThat(DomainCreatePermissions.getInstance(systemPermissionName), sameInstance(domainCreatePermission));
      }
   }

   @Test
   public void constructSystemPermission_withGrant_valid() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(domainCreatePermission.getPermissionName(), is(systemPermissionName));
         assertThat(domainCreatePermission.isSystemPermission(), is(true));
         assertThat(domainCreatePermission.isWithGrantOption(), is(true));
      }
   }

   @Test
   public void cacheSystemPermission_withGrant_valid() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(DomainCreatePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(domainCreatePermission));
      }
   }

   @Test
   public void constructCustomPermission_valid() {
      final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(domainPermission);
      assertThat(domainCreatePermission.getPostCreateDomainPermission(), is(domainPermission));
      assertThat(domainCreatePermission.isSystemPermission(), is(false));
      assertThat(domainCreatePermission.isWithGrantOption(), is(false));
   }

   @Test
   public void cacheCustomPermission_valid() {
      final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(domainPermission);
      assertThat(DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE)),
                 sameInstance(domainCreatePermission));
   }

   @Test
   public void constructCustomPermission_withGrant_valid() {
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstanceWithGrantOption(domainPermission);
      assertThat(domainCreatePermission.getPostCreateDomainPermission(), is(domainPermission));
      assertThat(domainCreatePermission.isSystemPermission(), is(false));
      assertThat(domainCreatePermission.isWithGrantOption(), is(true));
   }

   @Test
   public void cacheCustomPermission_withGrant_valid() {
      final DomainPermission domainPermission = DomainPermissions.getInstance(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstanceWithGrantOption(domainPermission);
      assertThat(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.DELETE)),
                 sameInstance(domainCreatePermission));
   }

   @Test
   public void constructSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(domainCreatePermission.getPermissionName(), is(systemPermissionName));
      }
      // now with grant
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(domainCreatePermission.getPermissionName(), is(systemPermissionName));
      }
   }

   @Test
   public void cacheSystemPermission_whitespaceConsistent() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(DomainCreatePermissions.getInstance(systemPermissionName), sameInstance(domainCreatePermission));
      }
      // now with grant
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(DomainCreatePermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(domainCreatePermission));
      }
   }

   @Test
   public void constructCustomPermission_whitespaceConsistent() {
      final String permissionName = DomainPermissions.DELETE;
      final DomainPermission domainPermission = DomainPermissions.getInstance(" " + permissionName + "\t");

      final DomainCreatePermission domainCreatePermission
            = DomainCreatePermissions.getInstance(domainPermission);
      assertThat(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName)),
                 is(domainCreatePermission));
      // now with grant
      final DomainCreatePermission grantableDomainCreatePermission
            = DomainCreatePermissions.getInstanceWithGrantOption(domainPermission);
      assertThat(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(permissionName)),
                 is(grantableDomainCreatePermission));
   }

   @Test
   public void cacheCustomPermission_whitespaceConsistent() {
      final String permissionName = DomainPermissions.DELETE;
      final DomainPermission domainPermission = DomainPermissions.getInstance(" " + permissionName + "\t");

      final DomainCreatePermission domainCreatePermission
            = DomainCreatePermissions.getInstance(domainPermission);
      assertThat(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName)),
                 sameInstance(domainCreatePermission));

      // now with grant
      final DomainCreatePermission grantableDomainCreatePermission
            = DomainCreatePermissions.getInstanceWithGrantOption(domainPermission);
      assertThat(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(permissionName)),
                 sameInstance(grantableDomainCreatePermission));
   }

   @Test
   public void constructSystemPermission_caseSensitiveConsistent() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            DomainCreatePermissions.getInstance(mixedCasePermissionName);
            fail("system permission names are case sensitive - creation of domain create permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now with grant
         try {
            DomainCreatePermissions.getInstanceWithGrantOption(mixedCasePermissionName);
            fail("system permission names are case sensitive - creation of domain permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void constructPermission_nulls_shouldFail() {
      try {
         DomainCreatePermissions.getInstance((String) null);
         fail("creation of domain create permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         DomainCreatePermissions.getInstance((DomainPermission) null);
         fail("creation of domain create permission with null post-create permission should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("post create domain permission is required"));
      }
      // now with grant
      try {
         DomainCreatePermissions.getInstanceWithGrantOption((String) null);
         fail("creation of domain create permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         DomainCreatePermissions.getInstanceWithGrantOption((DomainPermission) null);
         fail("creation of domain create permission with null post-create permission should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("post create domain permission is required"));
      }
   }

   @Test
   public void constructPermission_emptyNames_shouldFail() {
      try {
         DomainCreatePermissions.getInstance("");
         fail("creation of domain create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         DomainCreatePermissions.getInstance(" \t");
         fail("creation of domain create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      // now with grant
      try {
         DomainCreatePermissions.getInstanceWithGrantOption("");
         fail("creation of domain create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
      try {
         DomainCreatePermissions.getInstanceWithGrantOption(" \t");
         fail("creation of domain create permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name is required"));
      }
   }

   @Test
   public void constructSystemPermission_invalidSystemPermissionName_shouldFail() {
      try {
         DomainCreatePermissions.getInstance("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system domain create permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now with grant
      try {
         DomainCreatePermissions.getInstanceWithGrantOption("*this_is_an_invalid_system_permission_name_that_starts_with_asterisk");
         fail("creating system domain create permission with invalid system permission name should fail");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void serialize_internalPermissionImpl_shouldSucceed() throws IOException {
      final DomainPermission serializablePermission = DomainPermissions.getInstance(DomainPermissions.DELETE);
      final DomainCreatePermission DomainCreatePermission = DomainCreatePermissions.getInstance(serializablePermission);

      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(DomainCreatePermission);
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void serialize_customPermissionImpl_shouldSucceed() throws IOException {
      final DomainPermission nonSerializablePermission = new DomainPermission() {
         @Override
         public boolean isSystemPermission() { return true; }

         @Override
         public String getPermissionName() { return DomainPermissions.CREATE_CHILD_DOMAIN; }

         @Override
         public long getSystemPermissionId() { return -302; }

         @Override
         public boolean isWithGrantOption() { return false; }

         @Override
         public boolean isWithGrant() { return false; }

         @Override
         public boolean isGrantableFrom(DomainPermission other) { return false; }

         @Override
         public boolean equalsIgnoreGrantOption(Object other) { return false; }

         @Override
         public boolean equalsIgnoreGrant(Object other) { return false; }
      };

      final DomainCreatePermission DomainCreatePermission
            = DomainCreatePermissions.getInstance(nonSerializablePermission);

      ObjectOutputStream objectOutputStream = null;
      try {
         objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());
         objectOutputStream.writeObject(DomainCreatePermission);
      }
      finally {
         if (objectOutputStream != null) {
            objectOutputStream.close();
         }
      }
   }

   @Test
   public void toString_systemPermission() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstance(systemPermissionName);
         assertThat(domainCreatePermission.toString(), is(systemPermissionName));
      }
   }

   @Test
   public void toString_systemPermission_withGrant() {
      for(String systemPermissionName : DomainCreatePermissions.getSysPermissionNames()) {
         final DomainCreatePermission domainCreatePermission
               = DomainCreatePermissions.getInstanceWithGrantOption(systemPermissionName);
         final String stringRepresentation = domainCreatePermission.toString();
         assertThat(stringRepresentation, startsWith(systemPermissionName));
         assertThat(stringRepresentation, endsWith("/G"));
      }
   }

   @Test
   public void toString_customPermission() {
      final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission = DomainCreatePermissions.getInstance(domainPermission);
      final String stringRepresentation = domainCreatePermission.toString();
      assertThat(stringRepresentation, startsWith("["));
      assertThat(stringRepresentation, containsString(domainPermission.toString()));
      assertThat(stringRepresentation, endsWith("]"));
   }

   @Test
   public void toString_customPermission_withGrant() {
      final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE);
      final DomainCreatePermission domainCreatePermission
            = DomainCreatePermissions.getInstanceWithGrantOption(domainPermission);
      final String stringRepresentation = domainCreatePermission.toString();
      assertThat(stringRepresentation, startsWith("["));
      assertThat(stringRepresentation, containsString(domainPermission.toString()));
      assertThat(stringRepresentation, containsString("]"));
      assertThat(stringRepresentation, endsWith("/G"));
   }
}
