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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_revokeResourceCreatePermissions extends TestAccessControlBase {
   @Test
   public void revokeResourceCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_impersonate
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE), false);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true), true);
      final ResourceCreatePermission createPerm_resetPwd
            = ResourceCreatePermissions.getInstance(ResourcePermissions
                                                          .getInstance(ResourcePermissions.RESET_CREDENTIALS, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // set up accessor
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create_withGrant, createPerm_impersonate, createPerm_inherit_withGrant, createPerm_resetPwd);

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           createPerm_create_withGrant,
                                                           createPerm_impersonate,
                                                           createPerm_inherit_withGrant,
                                                           createPerm_resetPwd);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeResourceCreatePermissions_validAsAuthorized() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
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

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourceCreatePermissions.CREATE, false),
                                                           createPerm_inherit_withGrant);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeResourceCreatePermissions_validWithDefaultSessionDomain() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up the accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

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

      // revoke create permissions using the implicit session domain and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourceCreatePermissions.CREATE, false),
                                                           createPerm_inherit_withGrant);

      final Set<ResourceCreatePermission> resourceCreatePermissions_post
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(resourceCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeResourceCreatePermissions_ungrantedPermissions_shouldSucceedAsAuthorized() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // set up grantor
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

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourceCreatePermissions.CREATE, false),
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName).isEmpty(),
                 is(true));

      // revoke create permissions with implicit domain and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourceCreatePermissions
                                                                 .getInstance(ResourceCreatePermissions.CREATE, false),
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeResourceCreatePermissions_ungrantedPermissionsWithAndWithoutGrant_shouldFail() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission grantedCreatePerm
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);
      final ResourceCreatePermission ungrantedCreatePerm
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions = setOf(createPerm_create_withGrant,
                                                               grantedCreatePerm);

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

      // revoke create permissions and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_create_withGrant,
                                                              grantedCreatePerm,
                                                              ungrantedCreatePerm);
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedCreatePerm.toString().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(createPerm_create_withGrant.toString().toLowerCase())));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedCreatePerm.toString().toLowerCase())));
      }

      // revoke create permissions with implicit domain and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_create_withGrant,
                                                              grantedCreatePerm,
                                                              ungrantedCreatePerm);
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedCreatePerm.toString().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(createPerm_create_withGrant.toString().toLowerCase())));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedCreatePerm.toString().toLowerCase())));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_reRevokePermissions() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
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

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           createPerm_create_withGrant,
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName).isEmpty(),
                 is(true));

      // revoke create permissions again and verify that nothing changed
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           createPerm_create_withGrant,
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeResourceCreatePermissions_revokeSubsetOfPermissions() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourcePermission resourcePermission_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);
      final ResourceCreatePermission createPerm_impersonate_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_impersonate, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

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

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create, createPerm_impersonate_withGrant)));

      // revoke create permissions with implicit domain and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           createPerm_impersonate_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));
   }

   @Test
   public void revokeResourceCreatePermissions_revokeSubsetWithCreate_shouldFail() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourcePermission resourcePermission_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);
      final ResourceCreatePermission createPerm_impersonate_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_impersonate, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

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

      // revoke create permissions and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_inherit_withGrant,
                                                              createPerm_create);
         fail("revoking subset of permissions including *CREATE should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(
               "subset of resource create permissions that includes the *create"));
      }

      // revoke create permissions with implicit domain and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_inherit_withGrant,
                                                              createPerm_create);
         fail("revoking subset of permissions including *CREATE should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(
               "subset of resource create permissions that includes the *create"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
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
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));

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
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantablePermissionName), true));
      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      final String grantorDomain = accessControlContext.getDomainNameByResource(grantorResource);
      accessControlContext.setResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, grantorDomain),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourceCreatePermissions.CREATE),
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourcePermissions.getInstance(grantablePermissionName)),
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourcePermissions.getInstance(ungrantablePermissionName)));
         fail("revoking existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }

      // revoke create permissions with implicit domain and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourceCreatePermissions.CREATE),
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourcePermissions.getInstance(
                                                                          grantablePermissionName)),
                                                              ResourceCreatePermissions
                                                                    .getInstance(ResourcePermissions.getInstance(
                                                                          ungrantablePermissionName)));
         fail("revoking existing resource create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_ungrantedImpersonatePermissionOnUnauthenticatables_shouldFail() {
      final ResourcePermission resourcePermission_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourceCreatePermission createPerm_impersonate_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_impersonate, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke *IMPERSONATE system permission
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_impersonate_withGrant);
         fail("revoking impersonate create permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      // attempt to revoke *IMPERSONATE system permission with implicit domain
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_impersonate_withGrant);
         fail("revoking impersonate create permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_ungrantedResetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      final ResourcePermission resourcePermission_reset
            = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS);
      final ResourceCreatePermission createPerm_reset_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_reset, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke *RESET-CREDENTIALS system permission
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_reset_withGrant);
         fail("revoking reset-credentials create permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }

      // attempt to revoke *RESET-CREDENTIALS with implicit domain
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_reset_withGrant);
         fail("revoking reset-credentials create permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_identicalPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName3 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName4 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName5 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName6 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName7 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName8 = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      // set up the accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName7, true)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName8, true), true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName7, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName8, true), true));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke create permissions and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName1)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName2), true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5)),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6), true),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName7, true)),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName8, true), true))));

      // revoke create permissions with implicit domain and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName5)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName6), true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName7, true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName8, true), true));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));
   }

   @Test
   public void revokeResourceCreatePermissions_lesserPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName3 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName4 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName5 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName6 = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      // set up the accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6)));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true));

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke create permissions and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName1), true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName2, true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true), true));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4)),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5)),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6)))));

      // revoke create permissions with implicit domain and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName4), true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));
   }

   @Test
   public void revokeResourceCreatePermissions_greaterPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName3 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName4 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName5 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName6 = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);

      // set up the accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true));

      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant,
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName1, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName2, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName3, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true), true),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true));

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

      // revoke create permissions and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             domainName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName1),
                                                                true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName2,
                                                                                                true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions
                                                                      .getInstance(grantedPermissionName3)));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create,
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName4, true), true),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName5, true), true),
                          ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(grantedPermissionName6, true), true))));

      // revoke create permissions with implicit domain and verify
      accessControlContext
            .revokeResourceCreatePermissions(accessorResource,
                                             resourceClassName,
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName4),
                                                                true),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions.getInstance(grantedPermissionName5,
                                                                                                true)),
                                             ResourceCreatePermissions
                                                   .getInstance(ResourcePermissions
                                                                      .getInstance(grantedPermissionName6)));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));
   }

   @Test
   public void revokeResourceCreatePermissions_duplicatePermissions_shouldSucceed() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourcePermission resourcePermission_impersonate
            = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);
      final ResourceCreatePermission createPerm_impersonate_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_impersonate, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant, createPerm_impersonate_withGrant);

      accessControlContext.setResourceCreatePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorPermissions));

      // now authenticate as the granterResource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           createPerm_impersonate_withGrant,
                                                           createPerm_impersonate_withGrant);

      Set<ResourceCreatePermission> resourceCreatePermissions_expected
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false),
                    createPerm_inherit_withGrant);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_expected));

      // revoke duplicate create permissions for implicit domain
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName,
                                                           createPerm_inherit_withGrant,
                                                           createPerm_inherit_withGrant);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false))));
   }

   @Test
   public void revokeResourceCreatePermissions_duplicatePermissions_shouldFail() {
      final ResourcePermission resourcePermission_inherit_withGrant
            = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant);
      final ResourceCreatePermission createPerm_inherit_withGrant
            = ResourceCreatePermissions.getInstance(resourcePermission_inherit_withGrant, true);

      authenticateSystemResource();
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set up accessorResource
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      Set<ResourceCreatePermission> resourceCreatePermissions_pre
            = setOf(createPerm_create, createPerm_inherit_withGrant);

      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        resourceCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(resourceCreatePermissions_pre));

      // set up grantor
      Set<ResourceCreatePermission> grantorPermissions
            = setOf(createPerm_create_withGrant, createPerm_inherit_withGrant);

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

      // revoke create permissions and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_inherit,
                                                              createPerm_inherit_withGrant);
         fail("revoking create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      // revoke create permissions with implicit domain and verify
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_inherit,
                                                              createPerm_inherit_withGrant);
         fail("revoking create-permissions that include the same permission, but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final ResourceCreatePermission createPerm_create
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, false);
      final ResourceCreatePermission createPerm_customPerm
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName), false);
      final ResourceCreatePermission createPerm_customPerm_ws
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(permissionName + " \t"), false);

      // set up accessor
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      final Set<ResourceCreatePermission> permissions_pre = setOf(createPerm_create, createPerm_customPerm);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(permissions_pre));

      // revoke create permissions and verify
      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           createPerm_customPerm_ws);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));

      // revoke create permissions with implicit domain and verify
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        permissions_pre);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource,
                                                                            resourceClassName),
                 is(permissions_pre));

      accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           createPerm_customPerm_ws);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName),
                 is(setOf(createPerm_create)));
   }

   @Test
   public void revokeResourceCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_inherit
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke create permissions with null parameters
      try {
         accessControlContext.revokeResourceCreatePermissions(null,
                                                              resourceClassName,
                                                              createPerm_create_withGrant,
                                                              createPerm_inherit);
         fail("revoking create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(null,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_create_withGrant,
                                                              createPerm_inherit);
         fail("revoking create-permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              null,
                                                              createPerm_create_withGrant,
                                                              createPerm_inherit);
         fail("revoking create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              null,
                                                              domainName,
                                                              createPerm_create_withGrant,
                                                              createPerm_inherit);
         fail("revoking create-permissions with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              null);
         fail("revoking create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              null);
         fail("revoking create-permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              createPerm_create_withGrant,
                                                              null);
         fail("revoking create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_create_withGrant,
                                                              null);
         fail("revoking create-permissions with null element in permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }

      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              (String) null,
                                                              createPerm_create_withGrant,
                                                              createPerm_inherit);
         fail("revoking create-permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final ResourceCreatePermission createPerm_create_withGrant
            = ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true);
      final ResourceCreatePermission createPerm_invalid
            = ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("invalid_permission", false));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke create permissions with invalid references
      try {
         accessControlContext.revokeResourceCreatePermissions(Resources.getInstance(-999L),
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_create_withGrant);
         fail("revoking create-permissions with reference to non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              "invalid_resource_class",
                                                              domainName,
                                                              createPerm_create_withGrant);
         fail("revoking create-permissions with reference to non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              "invalid_resource_domain",
                                                              createPerm_create_withGrant);
         fail("revoking create-permissions with reference to non-existent domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void revokeResourceCreatePermissions_mismatchedResourceClass_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);
      final ResourcePermission permission_valid
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));
      final ResourcePermission permission_invalid
            = ResourcePermissions.getInstance(generateResourceClassPermission(generateResourceClass(false, false)));

      final ResourceCreatePermission createPerm_valid
            = ResourceCreatePermissions.getInstance(permission_valid);
      final ResourceCreatePermission createPerm_invalid
            = ResourceCreatePermissions.getInstance(permission_invalid);

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke create permissions with invalid references
      try {
         accessControlContext.revokeResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              createPerm_valid,
                                                              createPerm_invalid);
         fail("revoking create-permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}
