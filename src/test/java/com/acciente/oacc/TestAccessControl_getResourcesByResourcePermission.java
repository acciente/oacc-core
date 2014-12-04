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
package com.acciente.oacc;

import org.junit.Test;

import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getResourcesByResourcePermission extends TestAccessControlBase {
   @Test
   public void getResourcesByResourcePermission_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);

      Set<Resource> resourcesByPermission = accessControlContext.getResourcesByResourcePermission(resourceClassName, ResourcePermission.getInstance(permissionName));
      assertThat(resourcesByPermission.isEmpty(), is(true));
   }
}
