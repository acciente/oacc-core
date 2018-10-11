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

import java.util.List;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getResourceClassNames extends TestAccessControlBase {
   @Test
   public void getResourceClassNames_empty_asSystemResource() {
      authenticateSystemResource();

      // verify
      final List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames, is(not(nullValue())));
      assertThat(resourceClassNames.isEmpty(), is(true));
   }

   @Test
   public void getResourceClassNames_validAsSystemResource() {
      authenticateSystemResource();

      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(false, true);

      // verify
      final List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames, is(not(nullValue())));
      assertThat(resourceClassNames.size(), is(2));
      assertThat(resourceClassNames, hasItems(resourceClassName1, resourceClassName2));
   }

   @Test
   public void getResourceClassNames_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorResourceClassName
            = accessControlContext.getResourceClassInfoByResource(accessorResource).getResourceClassName();

      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(false, true);

      // authenticate and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames, is(not(nullValue())));
      assertThat(resourceClassNames.size(), is(3));
      assertThat(resourceClassNames, hasItems(resourceClassName1, resourceClassName2, accessorResourceClassName));
   }
}
