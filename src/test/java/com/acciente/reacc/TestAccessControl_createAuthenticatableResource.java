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
package com.acciente.reacc;

import org.junit.Test;

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createAuthenticatableResource extends TestAccessControlBase {
   @Test
   public void createAuthenticatableResource_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // create resource and verify
      final Resource resource = accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);

      assertThat(resource, is(not(nullValue())));
      accessControlContext.authenticate(resource, password);
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
   }

   @Test
   public void createAuthenticatableResource_validAsAuthorized() throws AccessControlException {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();
      final String password2 = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermission.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource and verify
      final Resource resource = accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

      // create another resource
      final Resource resource2 = accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password2);

      assertThat(resource2, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource2.getId(), is(not(resource.getId())));
      assertThat(accessControlContext.getDomainNameByResource(resource2), is(domainName));
      final ResourceClassInfo resourceClassInfo2 = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo2.getResourceClassName(), is(resourceClassName));

      // verify we can authenticate
      accessControlContext.authenticate(resource, password);
      accessControlContext.authenticate(resource2, password2);
   }

   @Test
   public void createAuthenticatableResource_validAsUnauthenticated() throws AccessControlException {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, true);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = generateResourceClassPermission(resourceClassName);
      final String password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName);

      final ResourcePermission implicitResourcePermission = ResourcePermission.getInstance(permissionName);
      final ResourcePermission implicitResourcePermission2 = ResourcePermission.getInstance(permissionName2);
      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));
      Set<Resource> resourcesByPermission2 = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission2);
      assertThat(resourcesByPermission2.isEmpty(), is(true));

      // create resource while unauthenticated and verify
      accessControlContext.unauthenticate();
      final Resource resource = accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);

      assertThat(resource, is(not(nullValue())));
      // re-authenticate as System Resource (because we don't have the previous credentials) and verify created resource
      authenticateSystemResource();
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

      // verify resource created while unauthenticated gets *ALL* available resource class permissions
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      resourcesByPermission2 = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission2);
      assertThat(resourcesByPermission2.size(), is(1));

      // verify we can authenticate
      accessControlContext.authenticate(resource, password);
   }

   @Test
   public void createAuthenticatableResource_validWithDefaultSessionDomain() throws AccessControlException {
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String domainName = accessControlContext.getDomainNameByResource(authenticatedResource);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermission.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource and verify
      final Resource resource = accessControlContext.createAuthenticatableResource(resourceClassName, password);

      assertThat(resource, is(not(nullValue())));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));

      // verify we can authenticate
      accessControlContext.authenticate(resource, password);
   }

   @Test
   public void createAuthenticatableResource_whitespaceConsistent_AsAuthorized() throws AccessControlException {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermission.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource with white-spaced names (and pwd) and verify
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String password_whitespaced = " " + password + "\t";
      final Resource whitespacedResource = accessControlContext.createAuthenticatableResource(resourceClassName_whitespaced, domainName_whitespaced, password);

      assertThat(whitespacedResource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));

      // create another resource WITHOUT white-spaced names and pwd
      final Resource resource = accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource.getId(), is(not(whitespacedResource.getId())));

      // verify passwords are whitespace-sensitive
      accessControlContext.authenticate(whitespacedResource, password);
      accessControlContext.authenticate(resource, password);
      try {
         accessControlContext.authenticate(whitespacedResource, password_whitespaced);
         fail("authentication of system resource with whitespace password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(resource, password_whitespaced);
         fail("authentication of system resource with whitespace password should not have succeeded");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
   }

   @Test
   public void createAuthenticatableResource_caseSensitiveConsistent_AsAuthorized() throws AccessControlException {
      authenticateSystemResource();
      final String domainBase = generateUniqueDomainName();
      final String resourceClassBase = generateUniqueResourceClassName();
      final String domain_lower = domainBase + "_ddd";
      final String domain_UPPER = domainBase + "_DDD";
      final String resourceClass_lower = resourceClassBase + "_ccc";
      final String resourceClass_UPPER = resourceClassBase + "_CCC";
      final String permissionName = generateUniquePermissionName();
      final String passwordBase = generateUniquePassword();
      final String password_lower = passwordBase + "_pwd";
      final String password_UPPER = passwordBase + "_PWD";
      accessControlContext.createDomain(domain_lower);
      accessControlContext.createResourceClass(resourceClass_lower,true,false);
      accessControlContext.createResourcePermission(resourceClass_lower, permissionName);

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createDomain(domain_UPPER);
         accessControlContext.createResourceClass(resourceClass_UPPER,true,false);
         accessControlContext.createResourcePermission(resourceClass_UPPER, permissionName);

         // set up an authenticatable resource with resource class create permission
         // and an extra permission in each domain/class combo, so that we can look up
         // the resources later via that permission
         final Resource authenticatedResource = generateResourceAndAuthenticate();
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_lower, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_UPPER, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_UPPER, domain_lower, permissionName);
         grantResourceCreatePermission(authenticatedResource, resourceClass_UPPER, domain_UPPER, permissionName);
         final ResourcePermission grantedResourcePermission_lower = ResourcePermission.getInstance(permissionName);
         final ResourcePermission grantedResourcePermission_UPPER = ResourcePermission.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in different domain/classes
         final Resource resource_lowlow = accessControlContext.createAuthenticatableResource(resourceClass_lower, domain_lower, password_lower);
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP = accessControlContext.createAuthenticatableResource(resourceClass_lower, domain_UPPER, password_UPPER);
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow = accessControlContext.createAuthenticatableResource(resourceClass_UPPER, domain_lower, password_lower);
         assertThat(resource_UPlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_UPUP = accessControlContext.createAuthenticatableResource(resourceClass_UPPER, domain_UPPER, password_UPPER);
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(2));

         // verify passwords are case-sensitive
         accessControlContext.authenticate(resource_lowlow, password_lower);
         accessControlContext.authenticate(resource_UPUP, password_UPPER);
         try {
            accessControlContext.authenticate(resource_lowlow, password_UPPER);
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (AccessControlException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
         try {
            accessControlContext.authenticate(resource_UPUP, password_lower);
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (AccessControlException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
      }
      else {
         // set up an authenticatable resource with resource class create permission
         // and an extra permission in each domain/class combo, so that we can look up
         // the resources later via that permission
         final Resource authenticatedResource = generateResourceAndAuthenticate();
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_lower, permissionName);
         final ResourcePermission grantedResourcePermission = ResourcePermission.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in different domain/classes
         final Resource resource_lowlow = accessControlContext.createAuthenticatableResource(resourceClass_lower, domain_lower, password_lower);
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP = accessControlContext.createAuthenticatableResource(resourceClass_lower, domain_UPPER, password_UPPER);
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow = accessControlContext.createAuthenticatableResource(resourceClass_UPPER, domain_lower, password_lower);
         assertThat(resource_UPlow, is(not(nullValue())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowUP.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(3));

         final Resource resource_UPUP = accessControlContext.createAuthenticatableResource(resourceClass_UPPER, domain_UPPER, password_UPPER);
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowUP.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(4));

         // verify passwords are case-sensitive
         accessControlContext.authenticate(resource_lowlow, password_lower);
         accessControlContext.authenticate(resource_UPUP, password_UPPER);
         try {
            accessControlContext.authenticate(resource_lowlow, password_UPPER);
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (AccessControlException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
         try {
            accessControlContext.authenticate(resource_UPUP, password_lower);
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (AccessControlException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
      }
   }

   @Test
   public void createAuthenticatableResource_unauthenticatableResourceClass_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String password = generateUniquePassword();

      // attempt to create authenticatable resource for unauthenticatable resource class
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);
         fail("creating authenticatable resource for unauthenticatable resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not permitted for resources of specified class"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, password);
         fail("creating authenticatable resource for unauthenticatable resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not permitted for resources of specified class"));
      }
   }

   @Test
   public void createAuthenticatableResource_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // attempt to create resources with null parameters
      try {
         accessControlContext.createAuthenticatableResource(null, password);
         fail("creating authenticatable resource with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, null);
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password expected"));
      }

      try {
         accessControlContext.createAuthenticatableResource(null, domainName, password);
         fail("creating authenticatable resource with null resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, null, password);
         fail("creating authenticatable resource with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, null);
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password expected"));
      }
   }

   @Test
   public void createAuthenticatableResource_invalidPassword_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String passwordBase = generateUniquePassword();
      final String whitespacedPwd = " " + passwordBase + "\t";
      final String tooShortPwd = (passwordBase + "123456").substring(0,5);

      // attempt to create authenticatable resource with invalid passwords
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, whitespacedPwd);
         fail("creating authenticatable resource with leading/trailing whitespace password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password may not contain leading/trailing spaces"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, tooShortPwd);
         fail("creating authenticatable resource with too short of a password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password must have at least"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, null);
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password expected"));
      }
   }

   @Test
   public void createAuthenticatableResource_blankNames_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // attempt to create authenticatable resources with empty or whitespaced parameters
      try {
         accessControlContext.createAuthenticatableResource("", password);
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createAuthenticatableResource(" \t", password);
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, "");
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password must have at least"));
      }
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, " \t");
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password may not contain leading/trailing spaces"));
      }

      try {
         accessControlContext.createAuthenticatableResource("", domainName, password);
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createAuthenticatableResource(" \t", domainName, password);
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, "", password);
         fail("creating authenticatable resource with empty domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, " \t", password);
         fail("creating authenticatable resource with empty domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, "");
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password must have at least"));
      }
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, " \t");
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password may not contain leading/trailing spaces"));
      }
   }

   @Test
   public void createAuthenticatableResource_nonExistantReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      // attempt to create authenticatable resources with non-existant references to class or domain names
      try {
         accessControlContext.createAuthenticatableResource("does_not_exist", password);
         fail("creating authenticatable resource with non-existant resource class name should fail");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.createAuthenticatableResource("does_not_exist", domainName, password);
         fail("creating authenticatable resource with non-existant resource class name should fail");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, "does_not_exist", password);
         fail("creating authenticatable resource with non-existant domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void createAuthenticatableResource_notAuthorized_shouldFail() throws AccessControlException {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      generateResourceAndAuthenticate();

      // attempt to create authenticatable resource without create-permission authorization
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, domainName, password);
         fail("creating authenticatable resource without authorization should fail");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }

   @Test
   public void createAuthenticatableResource_notAuthorizedWithDefaultSessionDomain_shouldFail() throws AccessControlException {
      final String resourceClassName = generateResourceClass(true, false);
      final String password = generateUniquePassword();

      generateResourceAndAuthenticate();

      // attempt to create authenticatable resource without create-permission authorization
      try {
         accessControlContext.createAuthenticatableResource(resourceClassName, password);
         fail("creating authenticatable resource without authorization should fail");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authorized"));
      }
   }
}
