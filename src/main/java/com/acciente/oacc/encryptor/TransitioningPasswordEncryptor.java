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

package com.acciente.oacc.encryptor;

import java.io.Serializable;

/**
 * The purpose of this password encryptor is to provide a means to transition from an existing (aka "old") password
 * encryptor to a new password encryptor in an environment where OACC is already deployed -- where existing passwords
 * in the tables are encrypted using the old password encryptor.
 */
public class TransitioningPasswordEncryptor implements PasswordEncryptor, Serializable {
   private final PasswordEncryptor newPasswordEncryptor;
   private final PasswordEncryptor oldPasswordEncryptor;

   /**
    * Creates a password encryptor that delegates all password hash encryption to the password encryptor provided in the
    * <code>newPasswordEncryptor</code> parameter. For decryption/comparison of existing passwords this password
    * encryptor first delegates to the password encryptor provided in the <code>newPasswordEncryptor</code> parameter if
    * that attempts fails by throwing an {@link IllegalArgumentException}, this password encryptor retries by
    * delegating to the password encryptor provided in the <code>oldPasswordEncryptor</code> parameter.
    *
    * @param newPasswordEncryptor the new password encryptor to use for hashing all new passwords hashes for storage
    * @param oldPasswordEncryptor the password encryptor that was to hash the passwords already stored in the tables, in
    *                             other words passwords that have not yet been updated since the transition to the
    *                             <code>newPasswordEncryptor</code> began.
    * @return a {@link TransitioningPasswordEncryptor} instance.
    */
   public static TransitioningPasswordEncryptor newInstance(PasswordEncryptor newPasswordEncryptor,
                                                            PasswordEncryptor oldPasswordEncryptor) {
      return new TransitioningPasswordEncryptor(newPasswordEncryptor, oldPasswordEncryptor);
   }

   private TransitioningPasswordEncryptor(PasswordEncryptor newPasswordEncryptor,
                                          PasswordEncryptor oldPasswordEncryptor) {
      this.newPasswordEncryptor = newPasswordEncryptor;
      this.oldPasswordEncryptor = oldPasswordEncryptor;
   }

   @Override
   public String encryptPassword(char[] password) {
      // encryption always uses the new password encryptor
      return newPasswordEncryptor.encryptPassword(password);
   }

   @Override
   public boolean checkPassword(char[] plainPassword, String encryptedPassword) {
      try {
         // first try the new password encryptor, this will work if the password was created by new password encryptor
         return newPasswordEncryptor.checkPassword(plainPassword, encryptedPassword);
      }
      catch (IllegalArgumentException e) {
         // if the new password encryptor fails with a password format exception, it is likely an old password, so
         // use the old password encryptor to decrypt the password
         return oldPasswordEncryptor.checkPassword(plainPassword, encryptedPassword);
      }
   }
}
