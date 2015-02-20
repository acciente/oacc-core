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

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createAuthenticatableResource extends TestAccessControlBase {
   @Test
   public void createAuthenticatableResource_validAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // create resource and verify
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName,
                                                                    PasswordCredentials.newInstance(password));

      assertThat(resource, is(not(nullValue())));
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));
   }

   @Test
   public void createAuthenticatableResource_validAsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();
      final char[] passwordBase = generateUniquePassword();
      final char[] shortPwd = (passwordBase + "123").substring(0,3).toCharArray();
      final char[] whitespacedPwd = (" " + passwordBase + "\t").toCharArray();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource and verify
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName,
                                                                    PasswordCredentials.newInstance(password));

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      final ResourceClassInfo resourceClassInfo = accessControlContext.getResourceClassInfoByResource(resource);
      assertThat(resourceClassInfo.getResourceClassName(), is(resourceClassName));

      // create another resource with a short password
      final Resource resource_shortPwd = accessControlContext.createResource(resourceClassName, domainName,
                                                                     PasswordCredentials.newInstance(shortPwd));

      assertThat(resource_shortPwd, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource_shortPwd.getId(), is(not(resource.getId())));
      assertThat(accessControlContext.getDomainNameByResource(resource_shortPwd), is(domainName));
      final ResourceClassInfo resourceClassInfo2 = accessControlContext.getResourceClassInfoByResource(resource_shortPwd);
      assertThat(resourceClassInfo2.getResourceClassName(), is(resourceClassName));

      // create another resource with a whitespaced password
      final Resource resource_whitespacedPwd = accessControlContext.createResource(resourceClassName, domainName,
                                                                     PasswordCredentials.newInstance(whitespacedPwd));

      assertThat(resource_whitespacedPwd, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(3));
      assertThat(resource_whitespacedPwd.getId(), is(not(resource.getId())));
      assertThat(resource_whitespacedPwd.getId(), is(not(resource_shortPwd.getId())));
      assertThat(accessControlContext.getDomainNameByResource(resource_whitespacedPwd), is(domainName));
      final ResourceClassInfo resourceClassInfo3 = accessControlContext.getResourceClassInfoByResource(resource_whitespacedPwd);
      assertThat(resourceClassInfo3.getResourceClassName(), is(resourceClassName));

      // verify we can authenticate
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
      accessControlContext.authenticate(resource_shortPwd, PasswordCredentials.newInstance(shortPwd));
      accessControlContext.authenticate(resource_whitespacedPwd, PasswordCredentials.newInstance(whitespacedPwd));
   }

   @Test
   public void createAuthenticatableResource_validAsUnauthenticated() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, true);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName);

      final ResourcePermission implicitResourcePermission = ResourcePermissions.getInstance(permissionName);
      final ResourcePermission implicitResourcePermission2 = ResourcePermissions.getInstance(permissionName2);
      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));
      Set<Resource> resourcesByPermission2 = accessControlContext.getResourcesByResourcePermission(resourceClassName, implicitResourcePermission2);
      assertThat(resourcesByPermission2.isEmpty(), is(true));

      // create resource while unauthenticated and verify
      accessControlContext.unauthenticate();
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName,
                                                                    PasswordCredentials.newInstance(password));

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
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
   }

   @Test
   public void createAuthenticatableResource_validWithDefaultSessionDomain() {
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String domainName = accessControlContext.getDomainNameByResource(authenticatedResource);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource and verify
      final Resource resource = accessControlContext.createResource(resourceClassName,
                                                                    PasswordCredentials.newInstance(password));

      assertThat(resource, is(not(nullValue())));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));

      // verify we can authenticate
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
   }

   @Test
   public void createAuthenticatableResource_whitespaceConsistent_AsAuthorized() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // (ironically,) set up an authenticatable resource with resource class create permission
      final Resource authenticatedResource = generateResourceAndAuthenticate();
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);
      grantResourceCreatePermission(authenticatedResource, resourceClassName, domainName, permissionName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.isEmpty(), is(true));

      // create resource with white-spaced names (and pwd) and verify
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final char[] password_whitespaced = (" " + password + "\t").toCharArray();
      final Resource whitespacedResource = accessControlContext.createResource(resourceClassName_whitespaced,
                                                                               domainName_whitespaced,
                                                                               PasswordCredentials.newInstance(password));

      assertThat(whitespacedResource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(1));
      assertThat(accessControlContext.getDomainNameByResource(whitespacedResource), is(domainName));

      // create another resource WITHOUT white-spaced names and pwd
      final Resource resource = accessControlContext.createResource(resourceClassName, domainName,
                                                                    PasswordCredentials.newInstance(password));

      assertThat(resource, is(not(nullValue())));
      resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, grantedResourcePermission);
      assertThat(resourcesByPermission.size(), is(2));
      assertThat(resource.getId(), is(not(whitespacedResource.getId())));
      assertThat(accessControlContext.getDomainNameByResource(resource), is(domainName));

      // verify passwords are whitespace-sensitive
      accessControlContext.authenticate(whitespacedResource, PasswordCredentials.newInstance(password));
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
      try {
         accessControlContext.authenticate(whitespacedResource,
                                           PasswordCredentials.newInstance(password_whitespaced));
         fail("authentication of resource with extra leading/trailing password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }
      try {
         accessControlContext.authenticate(resource,
                                           PasswordCredentials.newInstance(password_whitespaced));
         fail("authentication of resource with extra leading/trailing password should not have succeeded");
      }
      catch (IncorrectCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
      }

      // verify we can authenticate
      accessControlContext.authenticate(resource, PasswordCredentials.newInstance(password));
      accessControlContext.authenticate(whitespacedResource, PasswordCredentials.newInstance(password));
   }

   @Test
   public void createAuthenticatableResource_caseSensitiveConsistent_AsAuthorized() {
      authenticateSystemResource();
      final String domainBase = generateUniqueDomainName();
      final String resourceClassBase = generateUniqueResourceClassName();
      final String domain_lower = domainBase + "_ddd";
      final String domain_UPPER = domainBase + "_DDD";
      final String resourceClass_lower = resourceClassBase + "_ccc";
      final String resourceClass_UPPER = resourceClassBase + "_CCC";
      final String permissionName = generateUniquePermissionName();
      final char[] passwordBase = generateUniquePassword();
      final char[] password_lower = (passwordBase + "_pwd").toCharArray();
      final char[] password_UPPER = (passwordBase + "_PWD").toCharArray();
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
         final ResourcePermission grantedResourcePermission_lower = ResourcePermissions.getInstance(permissionName);
         final ResourcePermission grantedResourcePermission_UPPER = ResourcePermissions.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in different domain/classes
         final Resource resource_lowlow =
               accessControlContext.createResource(resourceClass_lower, domain_lower,
                                                   PasswordCredentials.newInstance(password_lower));
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP
               = accessControlContext.createResource(resourceClass_lower, domain_UPPER,
                                                     PasswordCredentials.newInstance(password_UPPER));
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission_lower);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow =
               accessControlContext.createResource(resourceClass_UPPER,
                                                   domain_lower,
                                                   PasswordCredentials.newInstance(password_lower));
         assertThat(resource_UPlow, is(not(nullValue())));
         resourcesByPermission
               = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER,
                                                                       grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_UPUP =
               accessControlContext.createResource(resourceClass_UPPER,
                                                   domain_UPPER,
                                                   PasswordCredentials.newInstance(password_UPPER));
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission_UPPER);
         assertThat(resourcesByPermission.size(), is(2));

         // verify passwords are case-sensitive
         accessControlContext.authenticate(resource_lowlow, PasswordCredentials.newInstance(password_lower));
         accessControlContext.authenticate(resource_UPUP, PasswordCredentials.newInstance(password_UPPER));
         try {
            accessControlContext.authenticate(resource_lowlow, PasswordCredentials.newInstance(password_UPPER));
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (IncorrectCredentialsException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
         try {
            accessControlContext.authenticate(resource_UPUP, PasswordCredentials.newInstance(password_lower));
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (IncorrectCredentialsException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
      }
      else {
         // set up an authenticatable resource with resource class create permission
         // and an extra permission in each domain/class combo, so that we can look up
         // the resources later via that permission
         final Resource authenticatedResource = generateResourceAndAuthenticate();
         grantResourceCreatePermission(authenticatedResource, resourceClass_lower, domain_lower, permissionName);
         final ResourcePermission grantedResourcePermission = ResourcePermissions.getInstance(permissionName);

         Set<Resource> resourcesByPermission;
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.isEmpty(), is(true));

         // create resources with case-sensitive domain/class names and verify resources get created in different domain/classes
         final Resource resource_lowlow
               = accessControlContext.createResource(resourceClass_lower,
                                                     domain_lower,
                                                     PasswordCredentials.newInstance(password_lower));
         assertThat(resource_lowlow, is(not(nullValue())));
         resourcesByPermission
               = accessControlContext.getResourcesByResourcePermission(resourceClass_lower,
                                                                       grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(1));

         final Resource resource_lowUP
               = accessControlContext.createResource(resourceClass_lower,
                                                     domain_UPPER,
                                                     PasswordCredentials.newInstance(password_UPPER));
         assertThat(resource_lowUP, is(not(nullValue())));
         assertThat(resource_lowUP.getId(), is(not(resource_lowlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_lower, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(2));

         final Resource resource_UPlow
               = accessControlContext.createResource(resourceClass_UPPER,
                                                     domain_lower,
                                                     PasswordCredentials.newInstance(password_lower));
         assertThat(resource_UPlow, is(not(nullValue())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPlow.getId(), is(not(resource_lowUP.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(3));

         final Resource resource_UPUP
               = accessControlContext.createResource(resourceClass_UPPER,
                                                     domain_UPPER,
                                                     PasswordCredentials.newInstance(password_UPPER));
         assertThat(resource_UPUP, is(not(nullValue())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowlow.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_lowUP.getId())));
         assertThat(resource_UPUP.getId(), is(not(resource_UPlow.getId())));
         resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClass_UPPER, grantedResourcePermission);
         assertThat(resourcesByPermission.size(), is(4));

         // verify passwords are case-sensitive
         accessControlContext.authenticate(resource_lowlow, PasswordCredentials.newInstance(password_lower));
         accessControlContext.authenticate(resource_UPUP, PasswordCredentials.newInstance(password_UPPER));
         try {
            accessControlContext.authenticate(resource_lowlow, PasswordCredentials.newInstance(password_UPPER));
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (IncorrectCredentialsException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
         try {
            accessControlContext.authenticate(resource_UPUP, PasswordCredentials.newInstance(password_lower));
            fail("authentication of system resource with case-insensitive password should not have succeeded");
         }
         catch (IncorrectCredentialsException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("invalid password"));
         }
      }
   }

   @Test
   public void createAuthenticatableResource_unauthenticatableResourceClass_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final char[] password = generateUniquePassword();

      // attempt to create authenticatable resource for unauthenticatable resource class
      try {
         accessControlContext.createResource(resourceClassName, domainName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource for unauthenticatable resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials not supported, but specified"));
      }

      try {
         accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource for unauthenticatable resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials not supported, but specified"));
      }
   }

   @Test
   public void createAuthenticatableResource_nulls_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // attempt to create resources with null parameters
      try {
         accessControlContext.createResource(null, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, (Credentials) null);
         fail("creating authenticatable resource with null credentials should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required, none specified"));
      }

      try {
         accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance(null));
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }

      try {
         accessControlContext.createResource(null, domainName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, null, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, domainName, null);
         fail("creating authenticatable resource with null credentials should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required, none specified"));
      }

      try {
         accessControlContext.createResource(resourceClassName, domainName, PasswordCredentials.newInstance(null));
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }
   }

   @Test
   public void createAuthenticatableResource_invalidPassword_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);

      // attempt to create authenticatable resource with invalid passwords
      try {
         accessControlContext.createResource(resourceClassName, domainName, null);
         fail("creating authenticatable resource with null credentials should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("credentials required"));
      }

      try {
         accessControlContext.createResource(resourceClassName,
                                             domainName,
                                             PasswordCredentials.newInstance(null));
         fail("creating authenticatable resource with null password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password required, none specified"));
      }
   }

   @Test
   public void createAuthenticatableResource_blankNames_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // attempt to create authenticatable resources with empty or whitespaced parameters
      try {
         accessControlContext.createResource("", PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createResource(" \t", PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance("".toCharArray()));
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be zero length"));
      }
      try {
         accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance(" \t".toCharArray()));
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be blank"));
      }

      try {
         accessControlContext.createResource("", domainName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.createResource(" \t", domainName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.createResource(resourceClassName, "", PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.createResource(resourceClassName, " \t", PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with empty domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.createResource(resourceClassName,
                                             domainName,
                                             PasswordCredentials.newInstance("".toCharArray()));
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be zero length"));
      }
      try {
         accessControlContext.createResource(resourceClassName,
                                             domainName,
                                             PasswordCredentials.newInstance(" \t".toCharArray()));
         fail("creating authenticatable resource with empty password should have failed");
      }
      catch (InvalidCredentialsException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("password cannot be blank"));
      }
   }

   @Test
   public void createAuthenticatableResource_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      // attempt to create authenticatable resources with non-existent references to class or domain names
      try {
         accessControlContext.createResource("does_not_exist", PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with non-existent resource class name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.createResource("does_not_exist", domainName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with non-existent resource class name should fail");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.createResource(resourceClassName,
                                             "does_not_exist",
                                             PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource with non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void createAuthenticatableResource_notAuthorized_shouldFail() {
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      generateResourceAndAuthenticate();

      // attempt to create authenticatable resource without create-permission authorization
      try {
         accessControlContext.createResource(resourceClassName,
                                             domainName,
                                             PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("create resource"));
      }
   }

   @Test
   public void createAuthenticatableResource_notAuthorizedWithDefaultSessionDomain_shouldFail() {
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();

      generateResourceAndAuthenticate();

      // attempt to create authenticatable resource without create-permission authorization
      try {
         accessControlContext.createResource(resourceClassName, PasswordCredentials.newInstance(password));
         fail("creating authenticatable resource without authorization should fail");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("create resource"));
      }
   }
}
