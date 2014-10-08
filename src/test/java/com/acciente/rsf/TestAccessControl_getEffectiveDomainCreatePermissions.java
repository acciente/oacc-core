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
package com.acciente.rsf;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getEffectiveDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_emptyAsAuthenticated() throws AccessControlException {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();

      Set<DomainCreatePermission> domainCreatePermissions = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermission.getInstance(DomainPermission.getInstance(DomainPermission.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermission.getInstance(DomainCreatePermission.CREATE, true);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermission.getInstance(DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN), false);

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      // get domain create permissions and verify
      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void getEffectiveDomainCreatePermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveDomainCreatePermissions(null);
      }
      catch (NullPointerException e) {
      }
   }
}
