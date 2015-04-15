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

import org.hamcrest.Matcher;
import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_revokeDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void revokeDomainCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // set accessor permissions
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      setOf(domCreatePerm_superuser,
                                                            domCreatePerm_create_withGrant,
                                                            domCreatePerm_child));

      Set<DomainCreatePermission> domainCreatePermissions_expected
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_expected));

      // revoke domain create permissions and verify
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create_withGrant,
                                                         domCreatePerm_child);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create_withGrant,
                                                         domCreatePerm_child);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_ungrantedPermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new accessor resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create_withGrant,
                                                         domCreatePerm_child);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_ungrantedPermissionsWithAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new accessor resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      try {
         accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                            domCreatePerm_superuser,
                                                            domCreatePerm_create_withGrant,
                                                            domCreatePerm_child);
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(domCreatePerm_superuser.toString().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(domCreatePerm_child.toString().toLowerCase())));
         assertThat(e.getMessage().toLowerCase(), not(containsString(domCreatePerm_create_withGrant.toString().toLowerCase())));
      }
   }

   @Test
   public void revokeDomainCreatePermissions_reRevokePermissions() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE) ;
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);

      Resource accessorResource = generateUnauthenticatableResource();

      // initialize domain create permissions
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create, domCreatePerm_child_withGrant);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(
            accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));

      // revoke domain create permissions and verify
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create,
                                                         domCreatePerm_child_withGrant);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // revoke domain create permissions again and verify that nothing changed
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create,
                                                         domCreatePerm_child_withGrant);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_revokeSubsetOfPermissions() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_child);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(setOf(domCreatePerm_create_withGrant)));
   }

   @Test
   public void revokeDomainCreatePermissions_revokeSubsetWithCreate_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      try {
         accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                            domCreatePerm_child,
                                                            domCreatePerm_create_withGrant);
         fail("revoking subset of permissions including *CREATE should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("subset of domain create permissions that includes the *create"));
      }
   }

   @Test
   public void revokeDomainCreatePermissions_withUnauthorizedPermissionsGrantedElsewhere_shouldFailAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to revoke permissions as grantor and verify
      try {
         accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                            DomainCreatePermissions
                                                                  .getInstance(DomainPermissions.getInstance(
                                                                        grantablePermissionName)),
                                                            DomainCreatePermissions
                                                                  .getInstance(DomainPermissions.getInstance(
                                                                        ungrantablePermissionName)));
         fail("revoking existing domain create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }


   @Test
   public void revokeDomainCreatePermissions_identicalPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create, domCreatePerm_child_withGrant);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create,
                                                         domCreatePerm_child_withGrant);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_lesserPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser, domCreatePerm_create, domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser_withGrant,
                                                         domCreatePerm_create_withGrant,
                                                         domCreatePerm_child_withGrant);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_greaterPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER), true);
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(grantorResource, domainCreatePermissions_granter);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource),
                 is(domainCreatePermissions_granter));

      // now create a new resource and set its domainCreatePermissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_pre));

      // revoke the domain create permissions as grantor
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser,
                                                         domCreatePerm_create,
                                                         domCreatePerm_child);

      final Set<DomainCreatePermission> domainCreatePermissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post.isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final DomainCreatePermission domCreatePerm_superuser_trailingspaces
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t"));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(" \t" + DomainCreatePermissions.CREATE, true);

      // todo: arguably, system permissions should match in name exactly, but the API uses Strings, not Enums, and is otherwise whitespace-consistent
      //       this could pose some complications depending on if the system permission name is persisted from the passed string or derived from an authoritative source
      Resource accessorResource = generateUnauthenticatableResource();
      // set accessor permissions
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(domainCreatePermissions_pre));

      // revoke domain create permissions and verify
      accessControlContext.revokeDomainCreatePermissions(accessorResource,
                                                         domCreatePerm_superuser_trailingspaces,
                                                         domCreatePerm_create_withGrant);

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);

      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to revoke domain create permissions with nulls
      try {
         accessControlContext.revokeDomainCreatePermissions(null, domCreatePerm_create_withGrant);
         fail("revoking domain create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeDomainCreatePermissions(accessorResource, null);
         fail("revoking domain create permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.revokeDomainCreatePermissions(accessorResource, domCreatePerm_create_withGrant, null);
         fail("revoking domain create permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }
   }

   @Test
   public void revokeDomainCreatePermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // set accessor permissions
      Set<DomainCreatePermission> domainCreatePermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      accessControlContext.setDomainCreatePermissions(accessorResource,
                                                      domainCreatePermissions_pre);

      // setup grantor permissions WITHOUT grantable *CREATE
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke duplicate permissions and verify
      accessControlContext
            .revokeDomainCreatePermissions(accessorResource,
                                           DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                           DomainCreatePermissions
                                                 .getInstance(DomainPermissions.getInstance(grantedPermissionName)));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainCreatePermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to revoke duplicate permissions and verify
      try {
         accessControlContext
               .revokeDomainCreatePermissions(accessorResource,
                                              DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(grantedPermissionName),
                                                                 true));
         fail("revoking create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .revokeDomainCreatePermissions(accessorResource,
                                              DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                              DomainCreatePermissions
                                                    .getInstance(DomainPermissions.getInstance(grantedPermissionName,
                                                                                               true)));
         fail("revoking create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .revokeDomainCreatePermissions(accessorResource,
                                              DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                              DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));
         fail("revoking create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void revokeDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);

      // attempt to revoke domain create permissions with non-existent references
      try {
         accessControlContext.revokeDomainCreatePermissions(Resources.getInstance(-999L), domCreatePerm_create_withGrant);
         fail("revoking domain create permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }
}
