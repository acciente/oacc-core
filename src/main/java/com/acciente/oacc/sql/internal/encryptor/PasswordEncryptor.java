/*
 * Copyright 2009-2016, Acciente LLC
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
package com.acciente.oacc.sql.internal.encryptor;

public interface PasswordEncryptor {

   /**
    * Encrypts a password.
    *
    * @param password the plaintext password as a cleanable char[]
    * @return the BASE-64 digest of encrypting the specified password
    */
   String encryptPassword(char[] password);


   /**
    * Checks an unencrypted password against an encrypted one to see if they match.
    *
    * @param plainPassword the plaintext password as a cleanable char[]
    * @param encryptedPassword the (BASE-64) digest from an earlier encryption against which to check the plaintext password
    * @return true if passwords match, false otherwise
    */
   boolean checkPassword(char[] plainPassword,
                         String encryptedPassword);

}
