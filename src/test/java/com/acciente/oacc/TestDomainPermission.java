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

public class TestDomainPermission {
   @Test
   public void getSysPermissionNames() {
      assertThat(DomainPermissions.getSysPermissionNames().size(), is(3));
      assertThat(DomainPermissions.getSysPermissionNames(), hasItem(DomainPermissions.DELETE));
      assertThat(DomainPermissions.getSysPermissionNames(), hasItem(DomainPermissions.CREATE_CHILD_DOMAIN));
      assertThat(DomainPermissions.getSysPermissionNames(), hasItem(DomainPermissions.SUPER_USER));
   }

   @Test
   public void construct_valid() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         DomainPermissions.getInstance(systemPermissionName);
      }
   }

   @Test
   public void cache_valid() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         final DomainPermission domainPermission = DomainPermissions.getInstance(systemPermissionName);
         assertThat(DomainPermissions.getInstance(systemPermissionName), sameInstance(domainPermission));
      }
   }

   @Test
   public void construct_withGrant_valid() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         DomainPermissions.getInstanceWithGrantOption(systemPermissionName);
      }
   }

   @Test
   public void cache_withGrant_valid() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(systemPermissionName);
         assertThat(DomainPermissions.getInstanceWithGrantOption(systemPermissionName), sameInstance(domainPermission));
      }
   }

   @Test
   public void construct_whitespaceConsistent() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         assertThat(DomainPermissions.getInstance(" " + systemPermissionName + "\t").getPermissionName(),
                    is(systemPermissionName));
         assertThat(DomainPermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t").getPermissionName(),
                    is(systemPermissionName));
      }
   }

   @Test
   public void cache_whitespaceConsistent() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         final DomainPermission domainPermission
               = DomainPermissions.getInstance(" " + systemPermissionName + "\t");
         assertThat(DomainPermissions.getInstance(systemPermissionName),
                    sameInstance(domainPermission));
         final DomainPermission grantableDomainPermission
               = DomainPermissions.getInstanceWithGrantOption(" " + systemPermissionName + "\t");
         assertThat(DomainPermissions.getInstanceWithGrantOption(systemPermissionName),
                    sameInstance(grantableDomainPermission));
      }
   }

   @Test
   public void construct_caseSensitiveConsistent() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         String mixedCasePermissionName
               = systemPermissionName.substring(0, systemPermissionName.length()/2).toLowerCase()
               + systemPermissionName.substring(systemPermissionName.length()/2).toUpperCase();
         try {
            DomainPermissions.getInstance(mixedCasePermissionName);
            fail("domain permission names are case sensitive - creation of domain permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
         // now attempt with grant
         try {
            DomainPermissions.getInstanceWithGrantOption(mixedCasePermissionName);
            fail("domain permission names are case sensitive - creation of domain permission with case insensitive name should have failed");
         }
         catch (Exception e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
         }
      }
   }

   @Test
   public void construct_nulls_shouldFail() {
      try {
         DomainPermissions.getInstance((String) null);
         fail("creation of domain permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      // now attempt with grant
      try {
         DomainPermissions.getInstanceWithGrantOption(null);
         fail("creation of domain permission with null name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
   }

   @Test
   public void construct_asteriskPermissionPrefix_shouldFail() {
      try {
         DomainPermissions.getInstance("*invalid");
         fail("creation of domain permission with asterisk-prefixed name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now attempt with grant
      try {
         DomainPermissions.getInstanceWithGrantOption("*invalid");
         fail("creation of domain permission with asterisk-prefixed name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void construct_blankNames_shouldFail() {
      try {
         DomainPermissions.getInstance("");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      try {
         DomainPermissions.getInstance(" \t");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      // now attempt with grant
      try {
         DomainPermissions.getInstanceWithGrantOption("");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
      try {
         DomainPermissions.getInstanceWithGrantOption(" \t");
         fail("creation of domain permission with empty name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("system permission name is required"));
      }
   }

   @Test
   public void construct_nonSystemDomainPermission_shouldFail() {
      try {
         DomainPermissions.getInstance("invalid");
         fail("creation of domain permission non-system domain permission name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
      // now attempt with grant
      try {
         DomainPermissions.getInstanceWithGrantOption("invalid");
         fail("creation of domain permission non-system domain permission name should have failed");
      }
      catch (Exception e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid system permission name"));
      }
   }

   @Test
   public void toStringTest() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         final DomainPermission domainPermission = DomainPermissions.getInstance(systemPermissionName);
         assertThat(domainPermission.toString(), is(systemPermissionName));
      }
   }

   @Test
   public void toStringTest_withGrant() {
      for(String systemPermissionName : DomainPermissions.getSysPermissionNames()) {
         final DomainPermission domainPermission = DomainPermissions.getInstanceWithGrantOption(systemPermissionName);
         final String stringRepresentation = domainPermission.toString();
         assertThat(stringRepresentation, startsWith(systemPermissionName));
         assertThat(stringRepresentation, endsWith("/G"));
      }
   }
}
