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
package com.acciente.rsf.sql.internal;

import com.acciente.rsf.Resource;
import com.acciente.rsf.sql.internal.persister.id.Id;
import com.acciente.rsf.sql.internal.persister.id.ResourceId;

/**
 * Internal class.
 */
public class PasswordUtils {
   public static String computeBoundPassword(Resource resource, String password) {
      return computeBoundPassword(resource.getId(), password);
   }

   public static String computeBoundPassword(Id<ResourceId> resourceId, String password) {
      return computeBoundPassword(resourceId.getValue(), password);
   }

   public static String computeBoundPassword(long resourceId, String password) {
      return password + resourceId + password.substring(password.length() / 2);
   }
}
