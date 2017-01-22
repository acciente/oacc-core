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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_grantResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void grantResourceCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(createPerm_create_withGrant,
                    createPerm_impersonate,
                    createPerm_inherit_withGrant,
                    createPerm_resetPwd);

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          createPerm_create_withGrant,
                                                          createPerm_impersonate,
                                                          createPerm_inherit_withGrant,
                                                          createPerm_resetPwd);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_expected));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantResourceCreatePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(createPerm_create_withGrant,
                                                                createPerm_impersonate,
                                                                createPerm_inherit_withGrant,
                                                                createPerm_resetPwd));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_withExtId() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.RESET_CREDENTIALS));

      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(createPerm_create_withGrant,
                    createPerm_impersonate,
                    createPerm_inherit_withGrant,
                    createPerm_resetPwd);

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(Resources.getInstance(externalId),
                                                          resourceClassName,
                                                          domainName,
                                                          createPerm_create_withGrant,
                                                          createPerm_impersonate,
                                                          createPerm_inherit_withGrant,
                                                          createPerm_resetPwd);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_expected));

      // test set-based version
      final String externalId2 = generateUniqueExternalId();
      final Resource accessorResource2 = generateUnauthenticatableResourceWithExtId(externalId2);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantResourceCreatePermissions(Resources.getInstance(externalId2),
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(createPerm_create_withGrant,
                                                                createPerm_impersonate,
                                                                createPerm_inherit_withGrant,
                                                                createPerm_resetPwd));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_validAsAuthorized() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit_withGrant);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant,
                                                               createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE),
                                                          createPerm_inherit_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    createPerm_inherit_withGrant);
      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(resourceCreatePermissions_expected));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource2);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantResourceCreatePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourceCreatePermissions
                                                                      .getInstance(ResourceCreatePermissions.CREATE),
                                                                createPerm_inherit_withGrant));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantablePermissionName)));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourcePermissions.getInstance(grantablePermissionName)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based versions
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext.grantResourceCreatePermissions(accessorResource2,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(ResourceCreatePermissions
                                                                      .getInstance(ResourcePermissions.getInstance(
                                                                            grantablePermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_withAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantablePermissionName)));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting resource create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourceCreatePermissions.getInstance(
                                                                   ResourceCreatePermissions.CREATE),
                                                                   ResourceCreatePermissions.getInstance(
                                                                         ResourcePermissions.getInstance(
                                                                               grantablePermissionName)),
                                                                   ResourceCreatePermissions.getInstance(
                                                                         ResourcePermissions.getInstance(
                                                                               ungrantablePermissionName))));
         fail("granting resource create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantablePermissionName)));
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                             ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("granting existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourceCreatePermissions.getInstance(
                                                                   ResourceCreatePermissions.CREATE),
                                                                   ResourceCreatePermissions.getInstance(
                                                                         ResourcePermissions.getInstance(
                                                                               grantablePermissionName)),
                                                                   ResourceCreatePermissions.getInstance(
                                                                         ResourcePermissions.getInstance(
                                                                               ungrantablePermissionName))));
         fail("granting existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_regrantPermissions() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit_withGrant);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant,
                                                               createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource);

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          ResourceCreatePermissions
                                                                .getInstance(ResourceCreatePermissions.CREATE),
                                                          createPerm_inherit_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    createPerm_inherit_withGrant);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_expected));

      // regrant create permissions and verify nothing changed
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_expected));

      // regrant via set-based versions and verify nothing changed
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName,
                                                          domainName,
                                                          setOf(createPerm_inherit_withGrant));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstance(customPermissionName)));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)));


      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions
                                                                     .getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(customPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions
                                                                           .getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                                                  ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions.getInstance(
                                                              customPermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(customPermissionName)));


      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstanceWithGrantOption(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(customPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstanceWithGrantOption(ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT)),
                                                  ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions.getInstance(
                                                              customPermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));


      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantResourceCreatePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(
            grantablePermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      Set<ResourceCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            grantablePermissionName)));
      requestedPermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantablePermissionName)));

      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourceCreatePermissions.CREATE),
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("Downgrading (=removal of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               setOf(ResourceCreatePermissions
                                                           .getInstance(ResourceCreatePermissions.CREATE),
                                                     ResourceCreatePermissions
                                                           .getInstance(ResourcePermissions.getInstance(
                                                                 grantablePermissionName)),
                                                     ResourceCreatePermissions
                                                           .getInstance(ResourcePermissions.getInstance(
                                                                 ungrantablePermissionName))));
         fail("Downgrading (=removal of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstanceWithGrantOption(ResourcePermissions
                                                                     .getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                                            ResourceCreatePermissions
                                                  .getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstanceWithGrantOption(ResourcePermissions
                                                                           .getInstanceWithGrantOption(ResourcePermissions.INHERIT)
                                                        ),
                                                  ResourceCreatePermissions
                                                        .getInstanceWithGrantOption(ResourcePermissions.getInstance(
                                                                           grantedPermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstanceWithGrantOption(ResourcePermissions
                                                                     .getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstanceWithGrantOption(ResourcePermissions
                                                                           .getInstanceWithGrantOption(ResourcePermissions.INHERIT)),
                                                  ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRightsAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      Set<ResourceCreatePermission> permissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName)));

      final Set<ResourceCreatePermission> permissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      accessorPermissions_pre.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));
      grantorPermissions.add(ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions
                                                                         .getInstance(grantedPermissionName)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions.getInstance(
                                                                   ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName)),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName)));
         fail("Upgrading (=addition of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourceCreatePermissions.getInstance(
                                                                         ResourceCreatePermissions.CREATE),
                                                                   ResourceCreatePermissions
                                                                         .getInstance(ResourcePermissions.getInstance(grantedPermissionName)),
                                                                   ResourceCreatePermissions
                                                                         .getInstance(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName))));
         fail("Upgrading (=addition of granting rights) of create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourceCreatePermissions_incompatibleExistingPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(permissionName1)),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstance(permissionName2)));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(permissionName1)),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(permissionName2)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstanceWithGrantOption(ResourcePermissions.getInstance(permissionName1)));
         fail("granting resource create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstanceWithGrantOption(permissionName2)));
         fail("granting resource create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }

      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               setOf(ResourceCreatePermissions
                                                           .getInstanceWithGrantOption(ResourcePermissions
                                                                              .getInstance(permissionName1))));
         fail("granting resource create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName,
                                               domainName,
                                               setOf(ResourceCreatePermissions
                                                           .getInstance(ResourcePermissions.getInstanceWithGrantOption(permissionName2
                                                           ))));
         fail("granting resource create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_withoutCreate_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions without *CREATE system permission
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_inherit);
         fail("granting create-permissions without *CREATE system permission when accessor doesn't already have it, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("*create must be specified"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_inherit));
         fail("granting create-permissions without *CREATE system permission when accessor doesn't already have it, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("*create must be specified"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_withoutGrantableCreate_shouldSucceed() {
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<ResourceCreatePermission> accessorPermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE));

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setResourceCreatePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // set up the grantorResource
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant create permissions and verify
      accessControlContext
            .grantResourceCreatePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions
                          .getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext
            .grantResourceCreatePermissions(accessorResource2,
                                            resourceClassName,
                                            domainName,
                                            setOf(ResourceCreatePermissions
                                                        .getInstance(ResourcePermissions
                                                                           .getInstance(ResourcePermissions.INHERIT))));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("granting *RESET_CREDENTIALS system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourceCreatePermissions
                                                                         .getInstance(ResourceCreatePermissions.CREATE),
                                                                   ResourceCreatePermissions
                                                                         .getInstance(ResourcePermissions
                                                                                            .getInstance(
                                                                                                  ResourcePermissions.RESET_CREDENTIALS))));
         fail("granting *RESET_CREDENTIALS system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourcePermissions
                                                                                      .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("granting *IMPERSONATE system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(ResourceCreatePermissions
                                                                         .getInstance(ResourceCreatePermissions.CREATE),
                                                                   ResourceCreatePermissions
                                                                         .getInstance(ResourcePermissions
                                                                                            .getInstance(
                                                                                                  ResourcePermissions.IMPERSONATE))));
         fail("granting *IMPERSONATE system permission as a create permission on an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_mismatchedResourceClassAndPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName1 = generateResourceClassPermission(resourceClassName1);

      // attempt to grant global permissions for mismatched resource class and permission
      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName2,
                                               domainName,
                                               ResourceCreatePermissions
                                                     .getInstance(ResourcePermissions.getInstance(permissionName1)));
         fail("granting create permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext
               .grantResourceCreatePermissions(accessorResource,
                                               resourceClassName2,
                                               domainName,
                                               setOf(ResourceCreatePermissions
                                                           .getInstance(ResourcePermissions
                                                                              .getInstance(permissionName1))));
         fail("granting create permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_customPerm
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName));
      final ResourceCreatePermission createPerm_customPerm_ws
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName + " \t"));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // grant create permissions and verify
      accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          domainName_whitespaced,
                                                          createPerm_create,
                                                          createPerm_customPerm_ws);

      Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(createPerm_create);
      permissions_expected.add(createPerm_customPerm_ws);
      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post, is(permissions_expected));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm));     // whitespace is trimmed upon permission creation
      assertThat(resourceCreatePermissions_post, hasItem(createPerm_customPerm_ws));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource2).isEmpty(), is(true));

      accessControlContext.grantResourceCreatePermissions(accessorResource2,
                                                          resourceClassName_whitespaced,
                                                          domainName_whitespaced,
                                                          setOf(createPerm_create,
                                                                createPerm_customPerm_ws));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_expected));
   }

   @Test
   public void grantResourceCreatePermissions_caseSensitiveConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateUniquePermissionName();
      final String permissionName_lower = permissionName + "_ppp";
      final String permissionName_UPPER = permissionName + "_PPP";
      accessControlContext.createResourcePermission(resourceClassName, permissionName_lower);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_lower
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_lower));
      final ResourceCreatePermission createPerm_UPPER
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName_UPPER));

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createResourcePermission(resourceClassName, permissionName_UPPER);

         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         // grant create permissions and verify
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create,
                                                             createPerm_UPPER);

         Set<ResourceCreatePermission> permissions_expected = new HashSet<>();
         permissions_expected.add(createPerm_create);
         permissions_expected.add(createPerm_UPPER);
         final Set<ResourceCreatePermission> resourceCreatePermissions_post
               = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
         assertThat(resourceCreatePermissions_post, is(permissions_expected));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_create));
         assertThat(resourceCreatePermissions_post, hasItem(createPerm_UPPER));
         assertThat(resourceCreatePermissions_post, not(hasItem(createPerm_lower)));     // whitespace is trimmed upon permission creation

         // test set-based version
         final Resource accessorResource2 = generateUnauthenticatableResource();
         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource2).isEmpty(),
                    is(true));

         accessControlContext.grantResourceCreatePermissions(accessorResource2,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create,
                                                                   createPerm_UPPER));

         assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource2, resourceClassName, domainName),
                    is(permissions_expected));
      }
      else {
         assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

         // grant create permissions and verify
         try {
            accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                createPerm_create,
                                                                createPerm_UPPER);
            fail("granting resource create permission with the name of an existing permission that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
         }
         try {
            accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                                resourceClassName,
                                                                domainName,
                                                                setOf(createPerm_create,
                                                                      createPerm_UPPER));
            fail("granting resource create permission with the name of an existing permission that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
         }
      }
   }

   @Test
   public void grantResourceCreatePermissions_duplicateIdenticalPermissions_shouldFail() {
      final ResourcePermission resourcePermission_inherit
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT);
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(resourcePermission_inherit_withGrant);

      // set up the grantorResource
      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);

      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant,
                                                               createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // prep for the createPermissions to be assigned to the accessorResource
      final Resource accessorResource = generateUnauthenticatableResource();

      // grant create permissions and verify
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             ResourceCreatePermissions
                                                                   .getInstance(ResourceCreatePermissions.CREATE),
                                                             createPerm_inherit,
                                                             createPerm_inherit);
         fail("granting resource create permissions with duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions with "near" duplicates
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_inherit_withGrant,
                                                                   createPerm_inherit));
         fail("granting create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions with null parameters
      try {
         accessControlContext.grantResourceCreatePermissions(null,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(Resources.getInstance(null),
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             null,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             (ResourceCreatePermission) null);
         fail("granting create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             null);
         fail("granting create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             createPerm_create_withGrant,
                                                             createPerm_inherit);
         fail("granting create-permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(null,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_inherit));
         fail("granting create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(Resources.getInstance(null),
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_inherit));
         fail("granting create-permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             null,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_inherit));
         fail("granting create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             (Set<ResourceCreatePermission>) null);
         fail("granting create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   null));
         fail("granting create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_inherit));
         fail("granting create-permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions with null parameters
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             Collections.<ResourceCreatePermission>emptySet());
         fail("granting create-permissions with null permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void grantResourceCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstanceWithGrantOption(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_invalid
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission"));
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to grant create permissions with invalid references
      try {
         accessControlContext.grantResourceCreatePermissions(invalidResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(invalidExternalResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(mismatchedResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             "invalid_resource_class",
                                                             domainName,
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             "invalid_resource_domain",
                                                             createPerm_create_withGrant);
         fail("granting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             createPerm_create_withGrant,
                                                             createPerm_invalid);
         fail("granting create-permissions with reference to non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantResourceCreatePermissions(invalidResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant));
         fail("granting create-permissions with reference to non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(invalidExternalResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant));
         fail("granting create-permissions with reference to non-existent external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(mismatchedResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant));
         fail("granting create-permissions with reference to mismatched internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             "invalid_resource_class",
                                                             domainName,
                                                             setOf(createPerm_create_withGrant));
         fail("granting create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             "invalid_resource_domain",
                                                             setOf(createPerm_create_withGrant));
         fail("granting create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.grantResourceCreatePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             setOf(createPerm_create_withGrant,
                                                                   createPerm_invalid));
         fail("granting create-permissions with reference to non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
