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
package com.acciente.oacc.sql.internal;

import com.acciente.oacc.Resource;

public class PasswordUtils {
   /**
    * Computes a password string that is bound to the resource with which the password is
    * associated. As a result of this binding, if the encrypted password of resource A
    * were used to overwrite the encrypted password of a resource B, it would still not be
    * possible to authenticate as resource B using the password for resource A.
    * @param resource
    * @param password
    * @return
    */
   public static char[] computeBoundPassword(Resource resource, char[] password) {
      final char[] resIdAsCharArray = String.valueOf(resource.getId()).toCharArray();
      final int tailLength = password.length - password.length / 2;
      char[] boundPassword = new char[password.length + resIdAsCharArray.length + tailLength];

      System.arraycopy(password, 0, boundPassword, 0, password.length);
      System.arraycopy(resIdAsCharArray, 0, boundPassword, password.length, resIdAsCharArray.length);
      System.arraycopy(password, password.length / 2, boundPassword, password.length + resIdAsCharArray.length, tailLength);

      return boundPassword;
   }

   /**
    * This method zeroes out all the elements of the passed in character array
    * @param password a char array containing a password
    */
   public static void cleanPassword(char[] password) {
      if (password != null) {
         for (int i = 0; i < password.length; i++) {
            password[i] = 0;
         }
      }
   }
}
