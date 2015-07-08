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
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_grantDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void grantDomainCreatePermissions_validAsSystemResource() {
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

      // grant domain create permissions and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        domCreatePerm_superuser,
                                                        domCreatePerm_create_withGrant,
                                                        domCreatePerm_child);

      Set<DomainCreatePermission> domainCreatePermissions_expected
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(
            accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_expected));

      // test set-based version
      Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2).isEmpty(), is(true));

      // grant domain create permissions and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(domCreatePerm_superuser,
                                                              domCreatePerm_create_withGrant,
                                                              domCreatePerm_child));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(domainCreatePermissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_validAsAuthorized() {
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
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter
            = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_create_withGrant, domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(authenticatableResource, domainCreatePermissions_granter);

      Set<DomainCreatePermission> domainCreatePermissions_post;
      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(authenticatableResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_granter));

      // now create a new resource and try to grant domainCreatePermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
      Resource accessorResource2 = generateUnauthenticatableResource();


      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        domCreatePerm_superuser,
                                                        domCreatePerm_create_withGrant,
                                                        domCreatePerm_child);

      Set<DomainCreatePermission> domainCreatePermissions_expected
            = setOf(domCreatePerm_superuser, domCreatePerm_create_withGrant, domCreatePerm_child);
      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2).isEmpty(), is(true));
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(domCreatePerm_superuser,
                                                              domCreatePerm_create_withGrant,
                                                              domCreatePerm_child));

      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_regrantPermissions() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE) ;
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  true);

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));


      // initialize domain create permissions and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        domCreatePerm_superuser,
                                                        domCreatePerm_create,
                                                        domCreatePerm_child_withGrant);

      Set<DomainCreatePermission> domainCreatePermissions_expected
            = setOf(domCreatePerm_superuser, domCreatePerm_create, domCreatePerm_child_withGrant);
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(
            accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_expected));

      // reset domain create permissions and verify that nothing changed
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        domCreatePerm_superuser,
                                                        domCreatePerm_child_withGrant);

      final Set<DomainCreatePermission> domainCreatePermissions_post2 = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post2, is(domainCreatePermissions_expected));

      // reset domain create permissions via set-based version and verify that nothing changed
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        setOf(domCreatePerm_superuser,
                                                              domCreatePerm_child_withGrant));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(domainCreatePermissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_addPermission_withAndWithoutGrant_shouldFailAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainCreatePermissions.CREATE),
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions.getInstance(
                                                                       grantablePermissionName)),
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions.getInstance(
                                                                       ungrantablePermissionName)));
         fail("granting domain create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           setOf(DomainCreatePermissions
                                                                       .getInstance(DomainCreatePermissions.CREATE),
                                                                 DomainCreatePermissions
                                                                       .getInstance(DomainPermissions.getInstance(
                                                                             grantablePermissionName)),
                                                                 DomainCreatePermissions
                                                                       .getInstance(DomainPermissions.getInstance(
                                                                             ungrantablePermissionName))));
         fail("granting domain create permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantDomainCreatePermissions_addPermission_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions.getInstance(grantablePermissionName)));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                          DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName)),
                          DomainCreatePermissions.getInstance(DomainPermissions
                                                                    .getInstance(ungrantablePermissionName)))));

      // test set-based version
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(
                                                                                             grantablePermissionName))));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                          DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName)),
                          DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)))));
   }

   @Test
   public void grantDomainCreatePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFailAsAuthorized() {
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

      // attempt to grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions.getInstance(
                                                                       grantablePermissionName)),
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions.getInstance(
                                                                       ungrantablePermissionName)));
         fail("granting existing domain create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           setOf(DomainCreatePermissions
                                                                       .getInstance(DomainPermissions.getInstance(
                                                                             grantablePermissionName)),
                                                                 DomainCreatePermissions
                                                                       .getInstance(DomainPermissions.getInstance(
                                                                             ungrantablePermissionName))));
         fail("granting existing domain create permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void grantDomainCreatePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        DomainCreatePermissions
                                                              .getInstance(DomainCreatePermissions.CREATE),
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions
                                                                                 .getInstance(grantablePermissionName,
                                                                                              true)),
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions
                                                                                 .getInstance(ungrantablePermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(DomainCreatePermissions
                                                                    .getInstance(DomainCreatePermissions.CREATE),
                                                              DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(grantablePermissionName,
                                                                                                    true)),
                                                              DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(ungrantablePermissionName))));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantDomainCreatePermissions_downgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions
                                                                                 .getInstance(grantablePermissionName), true),
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions
                                                                                 .getInstance(ungrantablePermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(
                                                                                             grantablePermissionName),
                                                                                 true),
                                                              DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(
                                                                                             ungrantablePermissionName))));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantDomainCreatePermissions_downgradeGrantingAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        DomainCreatePermissions
                                                              .getInstance(DomainPermissions.getInstance(
                                                                    grantedPermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(accessorPermissions_pre));

      // test set-based version
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(DomainCreatePermissions
                                                                    .getInstance(DomainPermissions
                                                                                       .getInstance(
                                                                                             grantedPermissionName))));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));
   }

   @Test
   public void grantDomainCreatePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions
                                                                                    .getInstance(grantedPermissionName)),
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions
                                                                                    .getInstance(ungrantedPermissionName)));
         fail("Downgrading (=removal of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           setOf(DomainCreatePermissions
                                                                       .getInstance(DomainPermissions
                                                                                          .getInstance(
                                                                                                grantedPermissionName)),
                                                                 DomainCreatePermissions
                                                                       .getInstance(DomainPermissions
                                                                                          .getInstance(ungrantedPermissionName))));
         fail("Downgrading (=removal of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantDomainCreatePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantDomainCreatePermissions(accessorResource,
                                          DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(ungrantablePermissionName),
                                                             true),
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(grantablePermissionName,
                                                                                           true), true));

      Set<DomainCreatePermission> permissions_expected
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      accessControlContext
            .grantDomainCreatePermissions(accessorResource2,
                                          setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE,
                                                                                    true),
                                                DomainCreatePermissions
                                                      .getInstance(DomainPermissions.getInstance(
                                                            ungrantablePermissionName),
                                                                   true),
                                                DomainCreatePermissions
                                                      .getInstance(DomainPermissions
                                                                         .getInstance(grantablePermissionName, true),
                                                                   true)));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(permissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_upgradePostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantablePermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantDomainCreatePermissions(accessorResource,
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true)),
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true));

      Set<DomainCreatePermission> permissions_expected
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantablePermissionName, true), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      accessControlContext
            .grantDomainCreatePermissions(accessorResource2,
                                          setOf(DomainCreatePermissions
                                                      .getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true)),
                                                DomainCreatePermissions
                                                      .getInstance(DomainPermissions.getInstance(grantablePermissionName,
                                                                                                 true), true)));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(permissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_upgradeGrantingRightsAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String ungrantablePermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantDomainCreatePermissions(accessorResource,
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(ungrantablePermissionName,
                                                                                           true), true));

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions
                                     .getInstance(DomainPermissions.getInstance(ungrantablePermissionName, true), true));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));

      // grant permissions as grantor and verify
      accessControlContext
            .grantDomainCreatePermissions(accessorResource2,
                                          setOf(DomainCreatePermissions
                                                      .getInstance(DomainPermissions
                                                                         .getInstance(ungrantablePermissionName, true),
                                                                   true)));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(permissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions
                                                                                    .getInstance(grantedPermissionName)),
                                                           DomainCreatePermissions
                                                                 .getInstance(DomainPermissions
                                                                                    .getInstance(ungrantedPermissionName,
                                                                                                 true)));
         fail("Upgrading (=addition of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           setOf(DomainCreatePermissions
                                                                       .getInstance(DomainPermissions
                                                                                          .getInstance(
                                                                                                grantedPermissionName)),
                                                                 DomainCreatePermissions
                                                                       .getInstance(DomainPermissions
                                                                                          .getInstance(
                                                                                                ungrantedPermissionName,
                                                                                                true))));
         fail("Upgrading (=addition of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      } catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantDomainCreatePermissions_incompatibleExistingPermission_shouldFail() {
      authenticateSystemResource();
      final String permissionName1 = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String permissionName2 = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName1, true)),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName2), true));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName1, true), true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(permissionName2, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(permissionName1), true));
         fail("granting domain create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(permissionName2, true)));
         fail("granting domain create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             setOf(DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(permissionName1),
                                                                      true)));
         fail("granting domain create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             setOf(DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(permissionName2,
                                                                                                    true))));
         fail("granting domain create-permission that is incompatible with existing permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("incompatible with existing create permission"));
      }
   }

   @Test
   public void grantDomainCreatePermissions_withoutCreatePermission_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                  false);

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // attempt to grant domain create permissions without passing the *CREATE system permission should fail
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           domCreatePerm_superuser,
                                                           domCreatePerm_child);
         fail("granting domain create permissions without passing the *CREATE system permission, when accessor doesn't already have it, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("create must be specified"));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                           setOf(domCreatePerm_superuser, domCreatePerm_child));
         fail("granting domain create permissions without passing the *CREATE system permission, when accessor doesn't already have it, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("create must be specified"));
      }
   }

   @Test
   public void grantDomainCreatePermissions_withoutGrantableCreatePermission_shouldSucceed() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));
      accessControlContext.setDomainCreatePermissions(accessorResource2, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2), is(accessorPermissions_pre));

      // setup grantor permissions WITHOUT grantable *CREATE
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName, true), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext
            .grantDomainCreatePermissions(accessorResource,
                                          DomainCreatePermissions
                                                .getInstance(DomainPermissions.getInstance(grantedPermissionName)));

      Set<DomainCreatePermission> permissions_expected
            = setOf(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      permissions_expected.addAll(accessorPermissions_pre);

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      accessControlContext
            .grantDomainCreatePermissions(accessorResource2,
                                          setOf(DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName))));

      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                 is(permissions_expected));
   }

   @Test
   public void grantDomainCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final DomainCreatePermission domCreatePerm_superuser_trailingspaces
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t"));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(" \t" + DomainCreatePermissions.CREATE, true);

      // todo: arguably, system permissions should match in name exactly, but the API uses Strings, not Enums, and is otherwise whitespace-consistent
      //       this could pose some complications depending on if the system permission name is persisted from the passed string or derived from an authoritative source
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      // grant domain create permissions and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource,
                                                        domCreatePerm_superuser_trailingspaces,
                                                        domCreatePerm_create_withGrant);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertEquals(domainCreatePermissions_post,
                   setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                         DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER))));

      // test set-based version
      Resource accessorResource2 = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2).isEmpty(), is(true));

      // grant domain create permissions and verify
      accessControlContext.grantDomainCreatePermissions(accessorResource2,
                                                        setOf(domCreatePerm_superuser_trailingspaces,
                                                              domCreatePerm_create_withGrant));

      assertEquals(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource2),
                   setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                         DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER))));
   }

   @Test
   public void grantDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);

      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to grant domain create permissions with nulls
      try {
         accessControlContext.grantDomainCreatePermissions(null, domCreatePerm_create_withGrant);
         fail("granting domain create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource, (DomainCreatePermission) null);
         fail("granting domain create permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource, domCreatePerm_create_withGrant, null);
         fail("granting domain create permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("an array or a sequence"));
      }

      try {
         accessControlContext.grantDomainCreatePermissions(null, setOf(domCreatePerm_create_withGrant));
         fail("granting domain create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource, (Set<DomainCreatePermission>) null);
         fail("granting domain create permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource, setOf(domCreatePerm_create_withGrant, null));
         fail("granting domain create permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

   }

   @Test
   public void grantDomainCreatePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to grant domain create permissions with empty set of permissions
      try {
         accessControlContext.grantDomainCreatePermissions(accessorResource, Collections.<DomainCreatePermission>emptySet());
         fail("granting domain create permissions with null domain permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void grantDomainCreatePermissions_duplicateIdenticalPermissions_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup grantor permissions WITHOUT grantable *CREATE
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true),
                    DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName), true));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant duplicate permissions and verify
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName)));
         fail("granting domain create permissions with duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void grantDomainCreatePermissions_duplicatePermissions_shouldFail() {
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

      // attempt to grant duplicate permissions and verify
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName), true));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                             DomainCreatePermissions
                                                   .getInstance(DomainPermissions.getInstance(grantedPermissionName, true)));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                             DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                   DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(
                                                               grantedPermissionName)),
                                                   DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(
                                                               grantedPermissionName), true)));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                   DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(
                                                               grantedPermissionName)),
                                                   DomainCreatePermissions
                                                         .getInstance(DomainPermissions.getInstance(
                                                               grantedPermissionName,
                                                               true))));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .grantDomainCreatePermissions(accessorResource,
                                             setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                   DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE,
                                                                                       true)));
         fail("granting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, true);

      // attempt to grant domain create permissions with non-existent references
      try {
         accessControlContext.grantDomainCreatePermissions(Resources.getInstance(-999L), domCreatePerm_create_withGrant);
         fail("granting domain create permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantDomainCreatePermissions(Resources.getInstance(-999L), setOf(domCreatePerm_create_withGrant));
         fail("granting domain create permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
   }

}
