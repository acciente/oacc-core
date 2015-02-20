/*
 * Copyright 2009-2015, Acciente LLC
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

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
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

      final List<String> expectedPermissions = new ArrayList<>();
      expectedPermissions.add(permissionName);

      assertThat(accessControlContext.getResourcePermissionNames(resourceClassName), is(expectedPermissions));
   }

   @Test
   public void getResourcePermissionNames_whitespaceConsistent() {
      authenticateSystemResource();

      final Resource resource = generateUnauthenticatableResource();
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      final String resourceClassName = resourceClassInfo.getResourceClassName();
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";

      final String permissionName = generateResourceClassPermission(resourceClassName);

      final List<String> expectedPermissions = new ArrayList<>();
      expectedPermissions.add(permissionName);

      assertThat(accessControlContext.getResourcePermissionNames(resourceClassName_whitespaced), is(expectedPermissions));
   }

   @Test
   public void getResourcePermissionNames_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourcePermissionNames("does_not_exist").isEmpty(), is(true));
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
