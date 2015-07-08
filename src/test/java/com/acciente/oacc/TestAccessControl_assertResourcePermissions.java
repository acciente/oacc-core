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

import java.util.Collections;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertResourcePermissions extends TestAccessControlBase {
   @Test
   public void assertResourcePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      final Resource accessedResource = accessControlContext.createResource(resourceClassName,
                                                                            accessControlContext
                                                                                  .getDomainNameByResource(SYS_RESOURCE));

      // verify setup
      final Set<ResourcePermission> directResourcePermissions
            = accessControlContext.getResourcePermissions(SYS_RESOURCE, accessedResource);
      assertThat(directResourcePermissions.isEmpty(), is(true));

      // verify
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(customPermissionName),
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     accessedResource,
                                                     setOf(ResourcePermissions.getInstance(customPermissionName)));
      accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                     accessedResource,
                                                     setOf(ResourcePermissions
                                                                 .getInstance(customPermissionName),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT)));
   }

   @Test
   public void assertResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final Resource accessedResource
            = accessControlContext.createResource(resourceClassName,
                                                  accessControlContext.getDomainNameByResource(SYS_RESOURCE),
                                                  PasswordCredentials.newInstance(generateUniquePassword()));

      // verify setup
      final Set<ResourcePermission> allResourcePermissions
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(allResourcePermissions.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        ResourcePermissions.getInstance(customPermissionName));
         fail("asserting resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        ResourcePermissions.getInstance(customPermissionName),
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting multiple resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }

      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        setOf(ResourcePermissions
                                                                    .getInstance(customPermissionName),
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.INHERIT)));
         fail("asserting multiple resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
   }

   @Test
   public void assertResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
         fail("asserting resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
         fail("asserting resource permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void assertResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate resource with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        customPermission,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting direct and unauthorized resource permission for authenticated resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        setOf(customPermission,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.INHERIT)));
         fail("asserting direct and unauthorized resource permission for authenticated resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
   }

   @Test
   public void assertResourcePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     customPermission,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     setOf(customPermission,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT)));
   }

   @Test
   public void assertResourcePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName1 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission1_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName1);
      final ResourcePermission customPermission1_withGrant
            = ResourcePermissions.getInstance(customPermissionName1, true);

      final String customPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission2_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName2);
      final ResourcePermission customPermission2_withGrant
            = ResourcePermissions.getInstance(customPermissionName2, true);

      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission1_withGrant, customPermission2_withoutGrant));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     customPermission1_withoutGrant,
                                                     customPermission1_withGrant,
                                                     customPermission2_withoutGrant);

      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission2_withGrant);
         fail("asserting resource permission with grant when the one granted does not have grant should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }

      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     setOf(customPermission1_withoutGrant,
                                                           customPermission1_withGrant,
                                                           customPermission2_withoutGrant));

      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission2_withGrant));
         fail("asserting resource permission with grant when the one granted does not have grant should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have permission"));
      }
   }

   @Test
   public void assertResourcePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(donorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup global permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        accessedResourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup global permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        accessedResourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);

      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
   }

   @Test
   public void assertResourcePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup super-user domain permission on parent domain
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);

      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     customPermission,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     setOf(customPermission,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT)));
   }

   @Test
   public void assertResourcePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateAuthenticatableResource(generateUniquePassword(), accessedDomainName);
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup super-user domain permission on parent domain
      final Resource donorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(donorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);

      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     customPermission,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission));
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     setOf(customPermission,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT)));
   }

   @Test
   public void assertResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup unauthenticatable resource without any permissions
      final Resource unauthenticatableResource = generateUnauthenticatableResource();

      // verify
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                        ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting multiple implicit global resource permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        setOf(ResourcePermissions
                                                                    .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("asserting implicit resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        setOf(ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("asserting implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(SYS_RESOURCE,
                                                        unauthenticatableResource,
                                                        setOf(ResourcePermissions
                                                                    .getInstance(ResourcePermissions.INHERIT),
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("asserting multiple implicit global resource permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void assertResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      final String customPermissionName2 = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission2 = ResourcePermissions.getInstance(customPermissionName2);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(null, accessedResource, customPermission);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, (Resource) null, customPermission);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, (ResourcePermission) null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission, null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission, new ResourcePermission[] {null});
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        customPermission,
                                                        customPermission2,
                                                        null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based versions
      try {
         accessControlContext.assertResourcePermissions(null, accessedResource, setOf(customPermission));
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, (Resource) null, setOf(customPermission));
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, (Set<ResourcePermission>) null);
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(customPermission, null));
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void assertResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, Collections.<ResourcePermission>emptySet());
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void assertResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission);
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, customPermission, new ResourcePermission[] {});
   }

   @Test
   public void assertResourcePermissions_duplicatePermissions_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();

      // setup direct permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void assertResourcePermissions_duplicatePermissions_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();

      // setup direct permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));

      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     setOf(ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT, true)));
   }

   @Test
   public void assertResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource accessedResource = generateUnauthenticatableResource();
      final String accessedResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessedResource).getResourceClassName();

      // setup direct permissions
      final String customPermissionName = generateResourceClassPermission(accessedResourceClassName);
      final ResourcePermission customPermission = ResourcePermissions.getInstance(customPermissionName);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(customPermission));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      final Resource invalidResource = Resources.getInstance(-999L);
      final ResourcePermission invalidPermission = ResourcePermissions.getInstance("invalid_permission");

      try {
         accessControlContext.assertResourcePermissions(invalidResource, accessedResource, customPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, invalidResource, customPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine resource class for resource"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, invalidPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        customPermission,
                                                        invalidPermission);
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.assertResourcePermissions(invalidResource, accessedResource, setOf(customPermission));
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, invalidResource, setOf(customPermission));
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine resource class for resource"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource, accessedResource, setOf(invalidPermission));
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
      try {
         accessControlContext.assertResourcePermissions(accessorResource,
                                                        accessedResource,
                                                        setOf(customPermission, invalidPermission));
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
