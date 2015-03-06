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

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertPostCreateResourcePermissions extends TestAccessControlBase {
   @Test
   public void assertPostCreateResourcePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
   }

   @Test
   public void assertPostCreateResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(customPermissionName),
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting multiple post-create resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName),
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("asserting multiple post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessorDomain, true);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain, false);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    customCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant, customCreatePermission_accessedDomain_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               customPermission_forAccessedDomain);
   }

   @Test
   public void assertPostCreateResourcePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessorDomain, true);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain, false);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    customCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant, customCreatePermission_accessorDomain_withGrant)));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant, customCreatePermission_accessedDomain_withoutGrant)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  ResourcePermissions
                                                                        .getInstance(ResourcePermissions.INHERIT),
                                                                  customPermission_forAccessorDomain);
         fail("asserting direct and unauthorized post-create resource permission should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessorDomainName,
                                                                  ResourcePermissions
                                                                        .getInstance(ResourcePermissions.INHERIT),
                                                                  customPermission_forAccessorDomain);
         fail("asserting direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessedDomainName,
                                                                  ResourcePermissions
                                                                        .getInstance(ResourcePermissions.INHERIT),
                                                                  customPermission_forAccessedDomain);
         fail("asserting direct and unauthorized post-create resource permission for domain should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_multipleDirect_shouldSucceedAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);
      final ResourceCreatePermission customCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessorDomain, true);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain);
      final ResourceCreatePermission customCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(customPermission_forAccessedDomain, false);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    customCreatePermission_accessorDomain_withGrant);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                    customCreatePermission_accessedDomain_withoutGrant);


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant,
                          customCreatePermission_accessorDomain_withGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant,
                          customCreatePermission_accessedDomain_withoutGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               customPermission_forAccessorDomain);
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               customPermission_forAccessorDomain,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               customPermission_forAccessorDomain);
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               customPermission_forAccessorDomain,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               customPermission_forAccessedDomain);
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               customPermission_forAccessedDomain,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
   }

   @Test
   public void assertPostCreateResourcePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableCustomPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain, true);
      final ResourcePermission ungrantableCustomPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain, false);
      final ResourceCreatePermission grantableCustomCreatePermission_accessorDomain_withGrant
            = ResourceCreatePermissions.getInstance(grantableCustomPermission_forAccessorDomain, true);

      final String customPermissionName_accessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableCustomPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain, true);
      final ResourcePermission ungrantableCustomPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_accessedDomain, false);
      final ResourceCreatePermission ungrantableCustomCreatePermission_accessedDomain_withoutGrant
            = ResourceCreatePermissions.getInstance(ungrantableCustomPermission_forAccessedDomain, false);

      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessorDomainName,
                                    createPermission_withGrant,
                                    grantableCustomCreatePermission_accessorDomain_withGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      grantResourceCreatePermission(accessorResource,
                                    resourceClassName,
                                    accessedDomainName,
                                    createPermission_withoutGrant,
                                    ungrantableCustomCreatePermission_accessedDomain_withoutGrant,
                                    ResourceCreatePermissions
                                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));


      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForAccessorDomain,
                 is(setOf(createPermission_withGrant,
                          grantableCustomCreatePermission_accessorDomain_withGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      final Set<ResourceCreatePermission> allResourceCreatePermissionsForAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForAccessedDomain,
                 is(setOf(createPermission_withoutGrant,
                          ungrantableCustomCreatePermission_accessedDomain_withoutGrant,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)))));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               grantableCustomPermission_forAccessorDomain);
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               ungrantableCustomPermission_forAccessorDomain);
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  ungrantableCustomPermission_forAccessorDomain,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT,
                                                                                                  true));
         fail("asserting multiple direct post-create resource permission with exceeded and lesser granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               grantableCustomPermission_forAccessorDomain);
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               ungrantableCustomPermission_forAccessorDomain);
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessorDomainName,
                                                                  ungrantableCustomPermission_forAccessorDomain,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT,
                                                                                                  true));
         fail("asserting multiple direct post-create resource permission with exceeded and lesser granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               ungrantableCustomPermission_forAccessedDomain);
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessedDomainName,
                                                                  grantableCustomPermission_forAccessedDomain);
         fail("asserting post-create resource permission for a direct create permission (for a domain) with exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessedDomainName,
                                                                  grantableCustomPermission_forAccessedDomain,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT,
                                                                                                  true));
         fail("asserting post-create resource permission for a direct create permission (for a domain) with same and exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessedDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource intermediaryResource = generateUnauthenticatableResource();
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();

      // setup create permissions
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);
      // setup inheritance permission
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, intermediaryResource, resourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessedDomain = new HashSet<>();
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessedDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessedDomain, is(resourceCreatePermissions_forAccessedDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, intermediaryResource);
      assertThat(allResourcePermissionsForAccessorResource, is(resourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               customPermission_forAccessedDomain);
   }

   @Test
   public void assertPostCreateResourcePermissions_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain
            = ResourcePermissions.getInstance(customPermissionName_forIntermediaryDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource, resourceClassName, intermediaryDomainName, customPermissionName_forIntermediaryDomain);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermissions
                                                            .getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain, false));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forAccessorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               customPermission_forAccessorDomain,
                                                               customPermission_forIntermediaryDomain);
   }

   @Test
   public void assertPostCreateResourcePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain
            = ResourcePermissions.getInstance(customPermissionName_forIntermediaryDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final Resource donorResource = accessControlContext.createResource(generateResourceClass(false, false), accessorDomainName);
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(donorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(donorResource, resourceClassName, intermediaryDomainName, customPermissionName_forIntermediaryDomain);
      // setup inheritance permission
      Set<ResourcePermission> inheritanceResourcePermissions = new HashSet<>();
      inheritanceResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forDonorDomain = new HashSet<>();
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermissions
                                                         .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermissions
                                                         .getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDonorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDonorDomain, is(resourceCreatePermissions_forDonorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE, false));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermissions
                                                                .getInstance(customPermission_forIntermediaryDomain, false));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forDonorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource);
      assertThat(allResourcePermissionsForAccessorResource, is(inheritanceResourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               customPermission_forAccessorDomain,
                                                               customPermission_forIntermediaryDomain);
   }

   @Test
   public void assertPostCreateResourcePermissions_globalOnly_shouldFailAsAuthenticatedResource() {
      // special case where the requested permission hasn't been granted as a create permission
      // but will be available from the granted global permissions on the {resource class, domain}-tuple
      // Note that in this test case there is no *CREATE permission, and the test should thus fail
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup global permission
      Set<ResourcePermission> globalResourcePermissions
            = setOf(globalResourcePermission, ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        globalResourcePermissions);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  globalResourcePermission);
         fail("asserting post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                  globalResourcePermission);
         fail("asserting multiple post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }

      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessorDomainName,
                                                                  globalResourcePermission);
         fail("asserting post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessorDomainName,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                  globalResourcePermission);
         fail("asserting multiple post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_globalAndDirect_succeedsAsAuthenticatedResource() {
      // special case where some of the requested permission haven't been granted as a create permission
      // but will be available from the granted global permissions on the {resource class, domain}-tuple
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(globalPermissionName);
      final ResourcePermission customResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final ResourcePermission systemResourcePermission = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup direct resource create permissions
      final ResourceCreatePermission createPermission_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_custom
            = ResourceCreatePermissions.getInstance(customResourcePermission, false);
      final ResourceCreatePermission createPermission_system
            = ResourceCreatePermissions.getInstance(systemResourcePermission, false);
      Set<ResourceCreatePermission> resourceCreatePermissions
            = setOf(createPermission_create, createPermission_custom, createPermission_system);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        resourceCreatePermissions);
      // setup global permission
      Set<ResourcePermission> globalResourcePermissions
            = setOf(globalResourcePermission, ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        globalResourcePermissions);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allResourceCreatePermissionsForResourceClass.size(), is(3));
      assertThat(allResourceCreatePermissionsForResourceClass,
                 hasItems(createPermission_create, createPermission_custom, createPermission_system));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               globalResourcePermission,
                                                               customResourcePermission,
                                                               ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                               systemResourcePermission);

      // verify by domain
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               globalResourcePermission,
                                                               customResourcePermission,
                                                               ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                               systemResourcePermission);
   }

   @Test
   public void assertPostCreateResourcePermissions_globalWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup create permissions
      final ResourceCreatePermission createPermission_withoutGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPermission_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(createPermission_withGrant));
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomainName,
                                                        setOf(createPermission_withoutGrant));

      // setup global permission
      final String globalPermissionName1 = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableGlobalPermission1 = ResourcePermissions.getInstance(globalPermissionName1, true);
      final ResourcePermission ungrantableGlobalPermission1 = ResourcePermissions.getInstance(globalPermissionName1);
      final String globalPermissionName2 = generateResourceClassPermission(resourceClassName);
      final ResourcePermission grantableGlobalPermission2 = ResourcePermissions.getInstance(globalPermissionName2, true);
      final ResourcePermission ungrantableGlobalPermission2 = ResourcePermissions.getInstance(globalPermissionName2);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(grantableGlobalPermission1));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomainName,
                                                        setOf(ungrantableGlobalPermission2));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               grantableGlobalPermission1,
                                                               ungrantableGlobalPermission1);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               grantableGlobalPermission1,
                                                               ungrantableGlobalPermission1);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessedDomainName,
                                                               ungrantableGlobalPermission2);

      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessedDomainName,
                                                                  grantableGlobalPermission2);
         fail("asserting post-create resource permission for a global (create) permission (for a domain) with exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                                  resourceClassName,
                                                                  accessedDomainName,
                                                                  ungrantableGlobalPermission2,
                                                                  grantableGlobalPermission2);
         fail("asserting multiple post-create resource permission for a global (create) permission (for a domain) with same and exceeded granting rights should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup super-user domain permission
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessorDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               globalResourcePermission);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               globalResourcePermission);
   }

   @Test
   public void assertPostCreateResourcePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermissions.getInstance(customPermissionName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);

      // setup super-user domain permission
      final Resource donorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(donorResource,
                                                accessorDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               globalResourcePermission);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName,
                                                               accessorDomainName,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                               globalResourcePermission);
   }

   @Test
   public void assertPostCreateResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit resource create permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit resource create permission valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    domainName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    domainName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit resource create permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                    resourceClassName,
                                                    domainName,
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit resource create permission (for a domain) valid and invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify

      // asserting post-create resource permission (even when none has been granted) should succeed for system resource
      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName_whitespaced,
                                                               ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName_whitespaced,
                                                               domainName_whitespaced,
                                                               ResourcePermissions.getInstance(customPermissionName));
   }

   @Test
   public void assertPostCreateResourcePermissions_whitespaceConsistent_asAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermissions.getInstance(
            customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain = ResourcePermissions.getInstance(
            customPermissionName_forAccessedDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String accessedDomainName_whitespaced = " " + accessedDomainName + "\t";

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName_whitespaced,
                                                               customPermission_forAccessorDomain);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               resourceClassName_whitespaced,
                                                               accessedDomainName_whitespaced,
                                                               customPermission_forAccessedDomain);
   }


   @Test
   public void assertPostCreateResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertPostCreateResourcePermissions(null,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  null,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  null);
         fail("asserting post-create resource permission for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  new ResourcePermission[]{null});
         fail("asserting post-create resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                  null);
         fail("asserting post-create resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertPostCreateResourcePermissions(null,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  null,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  (String) null,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  null);
         fail("asserting post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  new ResourcePermission[]{null});
         fail("asserting post-create resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                                  null);
         fail("asserting post-create resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_emptyPermissions_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);

      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName);
         fail("asserting post-create resource permission for empty sequence of resource permissions should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  new ResourcePermission[]{});
         fail("asserting post-create resource permission for empty sequence of resource permissions should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName);
         fail("asserting post-create resource permission (by domain) for empty sequence of resource permissions should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  new ResourcePermission[]{});
         fail("asserting post-create resource permission (by domain) for empty sequence of resource permissions should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("non-empty"));
      }
   }

   @Test
   public void assertPostCreateResourcePermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                               resourceClassName,
                                                               domainName,
                                                               ResourcePermissions.getInstance(customPermissionName),
                                                               ResourcePermissions.getInstance(customPermissionName));
   }

   @Test
   public void assertPostCreateResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertPostCreateResourcePermissions(Resources.getInstance(-999L),
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission for invalid accessor resource reference should have failed for system resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  "invalid_resource_class",
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting post-create resource permission for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  ResourcePermissions.getInstance(customPermissionName),
                                                                  ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting post-create resource permission for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertPostCreateResourcePermissions(Resources.getInstance(-999L),
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for invalid accessor resource reference should have failed for system resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission(s) after creating"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  "invalid_resource_class",
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  "invalid_domain",
                                                                  ResourcePermissions.getInstance(customPermissionName));
         fail("asserting post-create resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting post-create resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermissions(SYS_RESOURCE,
                                                                  resourceClassName,
                                                                  domainName,
                                                                  ResourcePermissions.getInstance(customPermissionName),
                                                                  ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting post-create resource permission (by domain) for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}
