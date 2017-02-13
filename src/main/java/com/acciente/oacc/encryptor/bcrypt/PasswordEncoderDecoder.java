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

package com.acciente.oacc.encryptor.bcrypt;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

public class PasswordEncoderDecoder {
   private static final String MARKER = BCryptPasswordEncryptor.NAME + ":";

   /**
    * Encodes the OACC password header into the BCrypt string (OpenBSD standard BCrypt hash implementation).
    *
    * @param bcryptString the BCrypt string returned by an OpenBSD standard BCrypt hashing implementation that "includes
    *                     version, cost factor, salt and hash, separated by '$'" (from the Javadoc for
    *                     {@link OpenBSDBCrypt#generate(char[], byte[], int)}.
    * @return a fully-encoded password ready for persistent storage.
    */
   String encode(String bcryptString) {
      return MARKER + bcryptString;

   }

   /**
    * Decodes the encoded BCrypt string (OpenBSD standard BCrypt hash implementation) from an encoded password.
    *
    * @param encodedPassword an encoded password that was previously returned by {{@link #encode(String)}}.
    * @return a BCrypt string (OpenBSD standard BCrypt hashing implementation).
    */
   String decode(String encodedPassword) {
      if (encodedPassword.startsWith(MARKER)) {
         return encodedPassword.substring(MARKER.length());
      }
      else {
         throw new IllegalArgumentException("Unexpected marker for BCrypt password: " +
                                                  encodedPassword.substring(0, MARKER.length()));
      }
   }
}
