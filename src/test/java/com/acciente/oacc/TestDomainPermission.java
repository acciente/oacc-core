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

public class TestDomainPermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(DomainPermission.getSysPermissionNames().size(), is(2));
      assertThat(DomainPermission.getSysPermissionNames(), hasItem(DomainPermission.CREATE_CHILD_DOMAIN));
      assertThat(DomainPermission.getSysPermissionNames(), hasItem(DomainPermission.SUPER_USER));
   }

   @Test
   public void construct_valid() throws AccessControlException {
      for(String systemPermissionName : DomainPermission.getSysPermissionNames()) {
         DomainPermission.getInstance(systemPermissionName);
      }
   }

   @Test
   public void construct_withGrant_valid() {
      for(String systemPermissionName : DomainPermission.getSysPermissionNames()) {
         DomainPermission.getInstance(systemPermissionName, true);
      }
   }

   @Test
   public void construct_whitespaceConsistent() throws AccessControlException {
      for(String systemPermissionName : DomainPermission.getSysPermissionNames()) {
         DomainPermission.getInstance(" " + systemPermissionName + "\t");
         DomainPermission.getInstance(" " + systemPermissionName + "\t", false);
         DomainPermission.getInstance(" " + systemPermissionName + "\t", true);
      }
   }

   @Test
   public void construct_caseSensitiveConsistent() throws AccessControlException {
      for(String systemPermissionName : DomainPermission.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            DomainPermission.getInstance(mixedCasePermissionName);
            fail("domain permission names are case sensitive - creation of domain permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now attempt with grant
         try {
            DomainPermission.getInstance(mixedCasePermissionName, true);
            fail("domain permission names are case sensitive - creation of domain permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void construct_nulls_shouldFail() throws AccessControlException {
      try {
         DomainPermission.getInstance(null);
         fail("creation of domain permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      // now attempt with grant
      try {
         DomainPermission.getInstance(null, true);
         fail("creation of domain permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
   }

   @Test
   public void construct_asteriskPermissionPrefix_shouldFail() throws AccessControlException {
      try {
         DomainPermission.getInstance("*invalid");
         fail("creation of domain permission with asterisk-prefixed name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now attempt with grant
      try {
         DomainPermission.getInstance("*invalid", true);
         fail("creation of domain permission with asterisk-prefixed name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void construct_blankNames_shouldFail() throws AccessControlException {
      try {
         DomainPermission.getInstance("");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      try {
         DomainPermission.getInstance(" \t");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      // now attempt with grant
      try {
         DomainPermission.getInstance("", true);
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      try {
         DomainPermission.getInstance(" \t", true);
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
   }

   @Test
   public void construct_nonSystemDomainPermission_shouldFail() throws AccessControlException {
      try {
         DomainPermission.getInstance("invalid");
         fail("creation of domain permission non-system domain permission name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now attempt with grant
      try {
         DomainPermission.getInstance("invalid", true);
         fail("creation of domain permission non-system domain permission name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }
}
