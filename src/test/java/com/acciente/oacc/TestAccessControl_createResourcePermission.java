/*
 * Copyright 2009-2018, Acciente LLC
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

import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createResourcePermission extends TestAccessControlBase {
   // creating resource classes and resource permissions is only allowed
   // as a system resource, hence there won't be a ..._validAsAuthorized() test

   @Test
   public void createResourcePermission_validAsSystemResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName1 = generateUniquePermissionName();
      List<String> permissionNames;
      permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
      assertThat(permissionNames.size(), is(3));
      assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                           ResourcePermissions.QUERY,
                                           ResourcePermissions.INHERIT));

      // create permission and verify
      accessControlContext.createResourcePermission(resourceClassName, permissionName1);
      permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
      assertThat(permissionNames.size(), is(4));
      assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                           ResourcePermissions.QUERY,
                                           ResourcePermissions.INHERIT,
                                           permissionName1));

      // add another permission and verify
      final String permissionName2 = generateUniquePermissionName();
      accessControlContext.createResourcePermission(resourceClassName, permissionName2);
      permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
      assertThat(permissionNames.size(), is(5));
      assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                           ResourcePermissions.QUERY,
                                           ResourcePermissions.INHERIT,
                                           permissionName1,
                                           permissionName2));
   }

   @Test
   public void createResourcePermission_whitespaceConsistent() {
      authenticateSystemResource();

      final String resourceClassNameTrimmed = generateResourceClass(false, false).trim();
      final String resourceClassNameWhitespaced = "\t" + resourceClassNameTrimmed + " ";
      final String permissionNameTrimmed = generateUniquePermissionName().trim();
      final String permissionNameWhitespaced = " " + permissionNameTrimmed + "\t";
      List<String> permissionNames;
      permissionNames = accessControlContext.getResourcePermissionNames(resourceClassNameTrimmed);
      assertThat(permissionNames.size(), is(3));
      assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                           ResourcePermissions.QUERY,
                                           ResourcePermissions.INHERIT));

      // create permission and verify
      accessControlContext.createResourcePermission(resourceClassNameWhitespaced, permissionNameWhitespaced);
      permissionNames = accessControlContext.getResourcePermissionNames(resourceClassNameTrimmed);
      assertThat(permissionNames.size(), is(4));
      assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                           ResourcePermissions.QUERY,
                                           ResourcePermissions.INHERIT,
                                           permissionNameTrimmed));
   }

   @Test
   public void createResourcePermission_caseSensitiveConsistent() {
      authenticateSystemResource();

      final String permissionNameBase = generateUniquePermissionName();
      final String permissionName_lower = permissionNameBase + "_ppp";
      final String permissionName_UPPER = permissionNameBase + "_PPP";
      final String resourceClassNameBase = generateUniquePermissionName();
      final String resourceClassName_lower = resourceClassNameBase + "_ccc";
      accessControlContext.createResourceClass(resourceClassName_lower, false, false);
      List<String> permissionNames;

      if (isDatabaseCaseSensitive()) {
         final String resourceClassName_UPPER = resourceClassNameBase + "_CCC";
         accessControlContext.createResourceClass(resourceClassName_UPPER, false, false);

         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_lower);
         assertThat(permissionNames.size(), is(3));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT));
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_UPPER);
         assertThat(permissionNames.size(), is(3));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT));

         // create permission with case-sensitive class/permission name combinations and verify
         accessControlContext.createResourcePermission(resourceClassName_lower, permissionName_lower);
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_lower);
         assertThat(permissionNames.size(), is(4));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT,
                                              permissionName_lower));
         assertThat(permissionNames, not(hasItem(permissionName_UPPER)));

         accessControlContext.createResourcePermission(resourceClassName_UPPER, permissionName_lower);
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_UPPER);
         assertThat(permissionNames.size(), is(4));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.INHERIT,
                                              ResourcePermissions.QUERY,
                                              permissionName_lower));
         assertThat(permissionNames, not(hasItem(permissionName_UPPER)));

         accessControlContext.createResourcePermission(resourceClassName_lower, permissionName_UPPER);
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_lower);
         assertThat(permissionNames.size(), is(5));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.INHERIT,
                                              ResourcePermissions.QUERY,
                                              permissionName_lower,
                                              permissionName_UPPER));

         accessControlContext.createResourcePermission(resourceClassName_UPPER, permissionName_UPPER);
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_UPPER);
         assertThat(permissionNames.size(), is(5));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT,
                                              permissionName_lower,
                                              permissionName_UPPER));
      }
      else {
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_lower);
         assertThat(permissionNames.size(), is(3));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT));

         // create permission with case-sensitive class/permission name combinations and verify
         accessControlContext.createResourcePermission(resourceClassName_lower, permissionName_lower);
         permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName_lower);
         assertThat(permissionNames.size(), is(4));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT,
                                              permissionName_lower));
         assertThat(permissionNames, not(hasItem(permissionName_UPPER)));

         try {
            accessControlContext.createResourcePermission(resourceClassName_lower, permissionName_UPPER);
            fail("creating a resource permission with the name of an existing permission that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
         }
      }
   }

   @Test
   public void createResourcePermission_notAuthorized_shouldFail() {
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName().trim();

      generateResourceAndAuthenticate();
      try {
         accessControlContext.createResourcePermission(resourceClassName, permissionName);
         fail("creating resource permission without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("reserved for the system resource"));
      }
   }

   @Test
   public void createResourcePermission_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName();

      try {
         accessControlContext.createResourcePermission(null, permissionName);
         fail("creating resource permission with NULL resource class name should fail");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createResourcePermission(resourceClassName, null);
         fail("creating resource permission with NULL permission name should fail");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name may not be null"));
      }
   }

   @Test
   public void createResourcePermission_nonExistentResourceClass_shouldFail() {
      authenticateSystemResource();

      final String permissionName = generateUniquePermissionName();

      try {
         accessControlContext.createResourcePermission("does_not_exist", permissionName);
         fail("creating resource permission with non-existent resource class name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
   }

   @Test
   public void createResourcePermission_asteriskPermissionPrefix_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = "*" + generateUniquePermissionName();

      try {
         accessControlContext.createResourcePermission(resourceClassName, permissionName);
         fail("creating resource permission with asterisk-prefixed permission name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("asterisk"));
      }
   }

   @Test
   public void createResourcePermission_emptyPermission_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);

      try {
         accessControlContext.createResourcePermission(resourceClassName, "");
         fail("creating resource permission with empty permission name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission name may not be blank"));
      }
   }

   @Test
   public void createResourcePermission_duplicatePermission_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName();

      accessControlContext.createResourcePermission(resourceClassName, permissionName);

      try {
         accessControlContext.createResourcePermission(resourceClassName, permissionName);
         fail("creating resource permission with duplicate permission name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate"));
         List<String> permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
         assertThat(permissionNames.size(), is(4));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT,
                                              permissionName));
      }
      // check if whitespace makes a difference
      try {
         accessControlContext.createResourcePermission(resourceClassName, " " + permissionName + "\t");
         fail("creating resource permission with duplicate permission name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate"));
         List<String> permissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
         assertThat(permissionNames.size(), is(4));
         assertThat(permissionNames, hasItems(ResourcePermissions.DELETE,
                                              ResourcePermissions.QUERY,
                                              ResourcePermissions.INHERIT,
                                              permissionName));
      }
   }
}
