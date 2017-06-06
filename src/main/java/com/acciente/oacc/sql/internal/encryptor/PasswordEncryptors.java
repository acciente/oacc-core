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
package com.acciente.oacc.sql.internal.encryptor;

import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.encryptor.bcrypt.BCryptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;

import java.util.Arrays;
import java.util.List;

/**
 * Internally used helper class to get an instance of the {@link PasswordEncryptor} identified
 * by the name of the {@link PasswordEncryptor}. This is where the NAME constant that is expected to
 * be defined in every {@link PasswordEncryptor} implementation is used.
 */
public class PasswordEncryptors {
   private static final int BCRYPT_MIN_COST_FACTOR = 10;

   private static final String JASYPT_ALGORITHM       = "SHA-256";
   private static final int    JASYPT_ITERATIONS      = 100000;
   private static final int    JASYPT_SALT_SIZE_BYTES = 16;

   public static PasswordEncryptor getPasswordEncryptor(String encryptorName) {
      if (encryptorName == null) {
         throw new IllegalArgumentException("Encryptor name cannot be null");
      }

      if (encryptorName.equalsIgnoreCase(BCryptPasswordEncryptor.NAME)) {
         return BCryptPasswordEncryptor.newInstance(BCRYPT_MIN_COST_FACTOR);
      }

      if (encryptorName.equalsIgnoreCase(JasyptPasswordEncryptor.NAME)) {
         return JasyptPasswordEncryptor.newInstance(JASYPT_ALGORITHM, JASYPT_ITERATIONS, JASYPT_SALT_SIZE_BYTES);
      }

      throw new IllegalArgumentException("Encryptor name " + encryptorName + " not recognized");
   }

   public static List<String> getSupportedEncryptorNames() {
      return Arrays.asList(BCryptPasswordEncryptor.NAME, JasyptPasswordEncryptor.NAME);
   }
}
