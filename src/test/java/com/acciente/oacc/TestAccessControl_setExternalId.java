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

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setExternalId extends TestAccessControlBase {
   @Test
   public void setExternalId_validAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);
      assertThat(resource.getExternalId(), is(nullValue()));

      // set externalId and verify
      final String externalId = generateUniqueExternalId();
      final Resource resolvedResource = accessControlContext.setExternalId(resource, externalId);

      assertThat(resolvedResource, is(not(nullValue())));
      assertThat(resolvedResource.getId(), is(resource.getId()));
      assertThat(resolvedResource.getExternalId(), is(externalId));
   }

   @Test
   public void setExternalId_validAsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermissions(authenticatedResource,
                                                                                                   resourceClassName,
                                                                                                   grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      final Resource resource = accessControlContext.createResource(resourceClassName, domainName);
      assertThat(resource.getExternalId(), is(nullValue()));

      // set externalId and verify
      final String externalId = generateUniqueExternalId();
      final Resource resolvedResource = accessControlContext.setExternalId(resource, externalId);

      assertThat(resolvedResource, is(not(nullValue())));
      assertThat(resolvedResource.getId(), is(resource.getId()));
      assertThat(resolvedResource.getExternalId(), is(externalId));
   }

   @Test
   public void setExternalId_resetSameExtId_shouldSucceed() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName, externalId);
      assertThat(resource.getExternalId(), is(externalId));

      // reset externalId with same value and verify
      final Resource resolvedResource
            = accessControlContext.setExternalId(Resources.getInstance(resource.getId()), externalId);

      assertThat(resolvedResource, is(resource));
      assertThat(resolvedResource.getExternalId(), is(resource.getExternalId()));
   }

   @Test
   public void setExternalId_resetDifferentExtId_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName, externalId);
      assertThat(resource.getExternalId(), is(externalId));

      // attempt to reset externalId with different value
      try {
         accessControlContext.setExternalId(Resources.getInstance(resource.getId()), "invalid_" + externalId);
         fail("re-setting resource's external id with different value should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not reset"));
      }

      try {
         accessControlContext.setExternalId(resource, "invalid_" + externalId);
         fail("re-setting resource's external id with different value should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not reset"));
      }
   }

   @Test
   public void setExternalId_duplicateExternalId_shouldFail() {
      authenticateSystemResource();

      final String domainName1 = generateDomain();
      final String resourceClassName1 = generateResourceClass(false, false);
      final String domainName2 = generateDomain();
      final String resourceClassName2 = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();

      // create resource
      final Resource resource1 = accessControlContext.createResource(resourceClassName1, domainName1, externalId);
      assertThat(resource1.getExternalId(), is(externalId));

      final Resource resource2 = accessControlContext.createResource(resourceClassName2, domainName2);

      try {
         accessControlContext.setExternalId(resource2, externalId);
         fail("setting resource's external id with non-unique value should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("external id is not unique"));
      }
   }

   @Test
   public void setExternalId_caseSensitiveConsistent_duplicateExternalId_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();
      final String externalId_lower = externalId + "_eee";
      final String externalId_UPPER = externalId + "_EEE";

      // create resource
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName, externalId_lower);
      assertThat(resource.getExternalId(), is(externalId_lower));

      if (isDatabaseCaseSensitive()) {
         // attempt to reset with value that only differs in case
         try {
            accessControlContext.setExternalId(resource, externalId_UPPER);
            fail("re-setting resource's external id with value that only differs in case should fail for case-sensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("could not reset"));
         }
      }
      else {
         // reset with value that only differs in case
         final Resource resetResource = accessControlContext.setExternalId(resource, externalId_UPPER);
         assertThat(resetResource.getExternalId(), is(externalId_lower));
      }
   }

   @Test
   public void setExternalId_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();

      final Resource resource = accessControlContext.createResource(resourceClassName, generateDomain());

      // attempt to set resource's external id with null parameters
      try {
         accessControlContext.setExternalId(null, externalId);
         fail("setting resource's external id with null resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.setExternalId(resource, null);
         fail("setting resource's external id with null external id should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("external id required"));
      }
   }

   @Test
   public void setExternalId_emptyNames_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);

      final Resource resource = accessControlContext.createResource(resourceClassName, generateDomain());

      // attempt to set resource's external id with empty or whitespace parameters
      try {
         accessControlContext.setExternalId(resource, "");
         fail("setting resource's external id with empty external id should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("external id required"));
      }
      try {
         accessControlContext.setExternalId(resource, " \t");
         fail("setting resource's external id with empty external id should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("external id required"));
      }
   }

   @Test
   public void setExternalId_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String externalId = generateUniqueExternalId();

      // attempt to create resources with non-existent references to class or domain names
      try {
         accessControlContext.setExternalId(Resources.getInstance(-99L), externalId);
         fail("setting resource's external id with non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setExternalId(Resources.getInstance(externalId), externalId);
         fail("setting resource's external id with non-existent resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

   @Test
   public void setExternalId_notAuthorized_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String externalId = generateUniqueExternalId();
      Resource resource = accessControlContext.createResource(resourceClassName, domainName);

      // authenticate as accessor
      final Resource accessor = generateResourceAndAuthenticate();

      // attempt to set externalId without create-permission authorization
      try {
         accessControlContext.setExternalId(resource, externalId);
         fail("setting resource's external id without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessor).toLowerCase()
                                                                       + " is not authorized to set external id"));
      }
   }

   @Test
   public void setExternalId_notAuthorized_unauthenticatedCreateAllowed_shouldFail() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, true);
      final String externalId = generateUniqueExternalId();
      Resource resource = accessControlContext.createResource(resourceClassName, domainName);

      final Resource accessor = generateResourceAndAuthenticate();

      // attempt to set externalId without create-permission authorization
      try {
         accessControlContext.setExternalId(resource, externalId);
         fail("setting resource's external id without authorization on a resource from a class that allows unauthenticated creation should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessor).toLowerCase()
                                                                       + " is not authorized to set external id"));
      }
   }
}
