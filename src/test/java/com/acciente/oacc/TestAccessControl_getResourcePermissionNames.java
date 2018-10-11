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
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getResourcePermissionNames extends TestAccessControlBase {
   @Test
   public void getResourcePermissionNames_validAsSystemResource() {
      authenticateSystemResource();

      final Resource resource = generateUnauthenticatableResource();
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      final String resourceClassName = resourceClassInfo.getResourceClassName();

      final String permissionName = generateResourceClassPermission(resourceClassName);

      assertThat(accessControlContext.getResourcePermissionNames(resourceClassName).size(), is(4));
      assertThat(accessControlContext.getResourcePermissionNames(resourceClassName),
                 hasItems(permissionName,
                          ResourcePermissions.DELETE,
                          ResourcePermissions.QUERY,
                          ResourcePermissions.INHERIT));
   }

   @Test
   public void getResourcePermissionNames_unauthenticatableResourceClass() {
      authenticateSystemResource();

      final Resource resource = generateUnauthenticatableResource();
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      final String resourceClassName = resourceClassInfo.getResourceClassName();

      final String permissionName = generateResourceClassPermission(resourceClassName);

      final List<String> resourcePermissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
      assertThat(resourcePermissionNames.size(), is(4));
      assertThat(resourcePermissionNames, hasItems(permissionName,
                                                   ResourcePermissions.DELETE,
                                                   ResourcePermissions.QUERY,
                                                   ResourcePermissions.INHERIT));
   }

   @Test
   public void getResourcePermissionNames_authenticatableResourceClass() {
      authenticateSystemResource();

      final Resource resource = generateAuthenticatableResource(generateUniquePassword());
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      final String resourceClassName = resourceClassInfo.getResourceClassName();

      final String permissionName = generateResourceClassPermission(resourceClassName);

      final List<String> resourcePermissionNames = accessControlContext.getResourcePermissionNames(resourceClassName);
      assertThat(resourcePermissionNames.size(), is(6));
      assertThat(resourcePermissionNames, hasItems(permissionName,
                                                   ResourcePermissions.DELETE,
                                                   ResourcePermissions.QUERY,
                                                   ResourcePermissions.INHERIT,
                                                   ResourcePermissions.IMPERSONATE,
                                                   ResourcePermissions.RESET_CREDENTIALS));
   }

   @Test
   public void getResourcePermissionNames_whitespaceConsistent() {
      authenticateSystemResource();

      final Resource resource = generateUnauthenticatableResource();
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      final String resourceClassName = resourceClassInfo.getResourceClassName();
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";

      final String permissionName = generateResourceClassPermission(resourceClassName);

      final List<String> resourcePermissionNames = accessControlContext.getResourcePermissionNames(
            resourceClassName_whitespaced);
      assertThat(resourcePermissionNames.size(), is(4));
      assertThat(resourcePermissionNames, hasItems(permissionName,
                                                   ResourcePermissions.DELETE,
                                                   ResourcePermissions.QUERY,
                                                   ResourcePermissions.INHERIT));
   }

   @Test
   public void getResourcePermissionNames_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      try {
         accessControlContext.getResourcePermissionNames("does_not_exist");
         fail("getting resource permission names with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
   }

   @Test
   public void getResourcePermissionNames_nulls() {
      authenticateSystemResource();

      try {
         accessControlContext.getResourcePermissionNames(null);
         fail("getting resource permission names with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
   }
}
